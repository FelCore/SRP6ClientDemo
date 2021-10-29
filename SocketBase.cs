using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace SRP6ClientDemo
{
    public abstract class SocketBase : IDisposable
    {
        public const int READ_BLOCK_SIZE = 4096;

        private Socket _socket;
        private IPAddress _remoteAddress;
        private int _remotePort;

        public Socket Socket { get { return _socket; } }

        private MessageBuffer _readBuffer;
        private Queue<MessageBuffer> _writeQueue = new Queue<MessageBuffer>();

        private int _closed;
        private bool _closing;

        private int _isWritingAsync;

        private bool _disposed = false;
        public bool Disposed { get { return _disposed; } }

        private readonly AsyncCallback ReceiveDataCallback;
        private readonly AsyncCallback SendDataCallback;
        private SocketError _error;

        public IPAddress RemoteAddress { get { return _remoteAddress; } }
        public int RemotePort { get { return _remotePort; } }

        public bool LogException { get; protected set; }

        public SocketBase(Socket socket)
        {
            _socket = socket;

            _readBuffer = new MessageBuffer(READ_BLOCK_SIZE);

            ReceiveDataCallback = ReadHandlerInternal;
            SendDataCallback = WriteHandlerInternal;

            var ipEndPoint = socket.RemoteEndPoint as IPEndPoint;
            if (ipEndPoint == null)
            {
                Debug.Assert(false);
                _remoteAddress = IPAddress.None;
                return;
            }

            _remoteAddress = ipEndPoint.Address;
            _remotePort = ipEndPoint.Port;
        }

        ~SocketBase()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                CloseSocket();
                _socket.Dispose();
                _readBuffer.Dispose();

                while (_writeQueue.Count > 0)
                    _writeQueue.Dequeue().Dispose();
            }

            _disposed = true;
        }

        /// <summary>
        /// Marks the socket for closing after write buffer becomes empty
        /// </summary>
        public void DelayedCloseSocket()
        {
            _closing = true;
        }

        public bool IsOpen()
        {
            return _closed != 1 && !_closing;
        }

        public virtual void Start() { }

        public void CloseSocket()
        {
            if (Interlocked.Exchange(ref _closed, 1) == 1)
                return;

            if (_socket.Connected)
            {
                try
                {
                    _socket.Shutdown(SocketShutdown.Send);
                }
                catch (SocketException ex)
                {
                    Console.WriteLine("SocketBase::CloseSocket: {0} errored when shutting down socket: ({1})", _remoteAddress.ToString(), ex.Message);
                }
            }

            OnClose();
        }

        public MessageBuffer GetReadBuffer() { return _readBuffer; }

        protected void SetNoDelay(bool enable)
        {
            _socket.NoDelay = enable;
        }

        protected virtual void OnClose() { }

        protected virtual void ReadHandler() { }

        private void ReadHandlerInternal(IAsyncResult result)
        {
            switch (_error)
            {
                case SocketError.Success:
                case SocketError.IOPending:
                    break;
                default:
                    CloseSocket();
                    return;
            }

            try
            {
                if (!_socket.Connected)
                    return;

                var transferredBytes = _socket.EndReceive(result);

                if (transferredBytes == 0) // Handle TCP Shutdown
                {
                    CloseSocket();
                    return;
                }

                _readBuffer.WriteCompleted(transferredBytes);
                ReadHandler();
            }
            catch (Exception ex)
            {
                CloseSocket();

                if (LogException)
                {
                    Console.WriteLine("SocketBase::ReadHandlerInternal: {0} errored: ({1})", _remoteAddress.ToString(), ex.Message);
                }
            }
        }

        public void AsyncRead()
        {
            if (!IsOpen())
                return;

            _readBuffer.Normalize();
            _readBuffer.EnsureFreeSpace();

            try
            {
                _socket.BeginReceive(_readBuffer.Data(), _readBuffer.Wpos(), _readBuffer.GetRemainingSpace(),
                    SocketFlags.None, out _error, ReceiveDataCallback, null);
            }
            catch (Exception ex)
            {
                CloseSocket();

                if (LogException)
                {
                    Console.WriteLine("SocketBase::AsyncRead: {0} errored when _socket.BeginReceive: ({1})", _remoteAddress.ToString(), ex.Message);
                }
            }
        }

        private void WriteHandlerInternal(IAsyncResult result)
        {
            switch (_error)
            {
                case SocketError.Success:
                case SocketError.IOPending:
                    break;
                default:
                    CloseSocket();
                    return;
            }

            try
            {
                var transferedBytes = _socket.EndSend(result);

                _writeQueue.Peek().ReadCompleted(transferedBytes);

                if (_writeQueue.Peek().GetActiveSize() <= 0)
                    _writeQueue.Dequeue().Dispose();

                Interlocked.Exchange(ref _isWritingAsync, 0);

                if (_writeQueue.Count > 0)
                    AsyncProcessQueue();
                else if (_closing)
                    CloseSocket();
            }
            catch (Exception ex)
            {
                CloseSocket();

                if (LogException)
                {
                    Console.WriteLine("SocketBase::WriteHandlerInternal: {0} errored: ({1})", _remoteAddress.ToString(), ex.Message);
                }
            }
        }

        protected void AsyncProcessQueue()
        {
            if (_closed == 1)
                return;

            if (Interlocked.Exchange(ref _isWritingAsync, 1) == 1)
                return;

            MessageBuffer buffer = _writeQueue.Peek();

            try
            {
                _socket.BeginSend(buffer.Data(), buffer.Rpos(), buffer.GetActiveSize(),
                    SocketFlags.None, out _error, SendDataCallback, null);
            }
            catch (Exception ex)
            {
                CloseSocket();

                if (LogException)
                {
                    Console.WriteLine("SocketBase::AsyncProcessQueue: {0} errored when _socket.BeginSend: ({1})", _remoteAddress.ToString(), ex.Message);
                }
            }
        }

        public void QueuePacket(MessageBuffer buffer)
        {
            _writeQueue.Enqueue(buffer);

            AsyncProcessQueue();
        }

        public virtual bool Update()
        {
            if (_closed == 1)
                return false;

            return true;
        }
    }
}
