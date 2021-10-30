using System.Text;
using System.Numerics;
using System.Net.Sockets;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SRP6ClientDemo;

using static AuthResult;
using static AuthCmd;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LogonChallengeResponse_Header
{
    public AuthCmd Opcode;
    public byte Unk;
    public AuthResult Result;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct LogonChallengeResponse_Body
{
    public fixed byte B[32];
    public byte g_length;
    public fixed byte g[1];
    public byte N_length;
    public fixed byte N[32];
    public fixed byte Salt[32];
    public fixed byte CRCSalt[16];
    public byte SecurityFlags;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LogonChallengeResponse_PIN
{
    public uint Unk1;
    public ulong Unk2;
    public ulong Unk3;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LogonChallengeResponse_Matrix
{
    public byte Unk1;
    public byte Unk2;
    public byte Unk3;
    public byte Unk4;
    public ulong Unk5;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LogonChallengeResponse_Token
{
    public bool RequestToken;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LogonProofResponse_Header
{
    public AuthCmd Opcode;
    public AuthResult Result;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct LogonProofResponse_Error
{
    public byte Unk1;
    public byte Unk2;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct LogonProofResponse_Body
{
    public fixed byte M2[20];
    public uint AccountFlags;
    public uint SurveyId;
    public ushort Unk;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct RealmlistResponse_Header
{
    public AuthCmd Opcode;
    public ushort Length;
    public uint Unk;
    public ushort Count;
}

public unsafe class AuthSession : SocketBase
{
    const string AccountName = "srp6";
    const string AccountPassword = "aaa123";

    const string GameName = "WoW";
    byte[] GameVersion = new byte[] { 1, 12, 1 };
    const ushort GameBuild = 8606;
    const string Platform = "68x";
    const string OS = "niW";
    char[] Locale = new char[] { 'e', 'n', 'G', 'B' };
    const uint TimeZone = 0x3C;
    const uint IP = 0x0100007F;

    SRP6 _srp6;
    string _token = "";

    public AuthSession(Socket socket) : base(socket)
    {
        _srp6 = new();
    }

    public void SendPacket(ByteBuffer buffer)
    {
        if (buffer.Wpos() == 0) return;

        var msgBuffer = new MessageBuffer(buffer.Wpos());
        msgBuffer.Write(buffer.AsSpan(0, buffer.Wpos()));

        QueuePacket(msgBuffer);
    }

    string AuthResultToStr(AuthResult result)
    {
        switch (result)
        {
            case WOW_SUCCESS:
                return "Success!";
            case WOW_FAIL_BANNED:
                return "This World of Warcraft account has been closed and is no longer available for use. Please check your server's website for further information.";
            case WOW_FAIL_UNKNOWN_ACCOUNT:
            case WOW_FAIL_INCORRECT_PASSWORD:
                return "The information you have entered is not valid. Please check the spelling of the account name and password. If you need help in retrieving a lost or stolen password, see your server's website for more information.";
            case WOW_FAIL_ALREADY_ONLINE:
                return "This account is already logged into World of Warcraft. Please check the spelling and try again.";
            case WOW_FAIL_NO_TIME:
                return "You have used up your prepaid time for this account. Please purchase more to continue playing.";
            case WOW_FAIL_DB_BUSY:
                return "Could not log in to World of Warcraft at this time. Please try again later.";
            case WOW_FAIL_VERSION_INVALID:
                return "Unable to validate game version. This may be caused by file corruption or interference of another program. Please visit your server's website for more information and possible solutions to this issue.";
            case WOW_FAIL_VERSION_UPDATE:
                return "Downloading...";
            case WOW_FAIL_SUSPENDED:
                return "This World of Warcraft account has been temporarily suspended. Please visit your server's website for further information.";
            case WOW_SUCCESS_SURVEY:
                return "Connected.";
            case WOW_FAIL_PARENTCONTROL:
                return "Access to this account has been blocked by parental controls. Your settings may be changed in your account preferences at your server's website.";
            default:
                Debug.Assert(false);
                return "<Unknown>";
        }
    }

    public override void Start()
    {
        SendLogonChallenge();
        AsyncRead();
    }

    void SendLogonChallenge()
    {
        ByteBuffer packet = new();
        packet.Append((byte)AUTH_LOGON_CHALLENGE);
        packet.Append((byte)8);

        var accountNameLen = Encoding.UTF8.GetByteCount(AccountName);
        packet.Append((ushort)(accountNameLen + 30));

        packet.Append("WoW");
        packet.Append(GameVersion[0]);
        packet.Append(GameVersion[1]);
        packet.Append(GameVersion[2]);
        packet.Append(GameBuild);
        packet.Append(Platform);
        packet.Append(OS);
        packet.Append((byte)Locale[3]);
        packet.Append((byte)Locale[2]);
        packet.Append((byte)Locale[1]);
        packet.Append((byte)Locale[0]);
        packet.Append(TimeZone);
        packet.Append(IP);
        packet.Append((byte)accountNameLen);
        packet.Append(AccountName, false);

        SendPacket(packet);
    }

    void SendLogonProof()
    {
        // TODO: Implement CRC calculation
        BigInteger crc = new();
        crc.SetRandom(20 * 8);

        ByteBuffer packet = new();
        packet.Append((byte)AUTH_LOGON_PROOF);

        Span<byte> crcBytes = stackalloc byte[20];
        crc.TryWriteBytes(crcBytes, out var _, true);

        packet.Append(_srp6.GetClientEphemeralA());
        packet.Append(_srp6.GetClientM1());
        packet.Append(crcBytes);

        if (string.IsNullOrEmpty(_token))
        {
            packet.Append((byte)0);
            packet.Append((byte)0);
        }
        else
        {
            packet.Append((byte)1);
            packet.Append((byte)0x04);
            packet.Append((byte)(Encoding.UTF8.GetByteCount(_token) + 1));
            packet.Append(_token);
        }

        SendPacket(packet);
    }

    void SendRealmlistRequest()
    {
        ByteBuffer packet = new();
        packet.Append((byte)REALM_LIST);
        packet.Append((uint)0x1000);
        SendPacket(packet);
    }

    protected override void ReadHandler()
    {
        var packet = GetReadBuffer();
        while (packet.GetActiveSize() > 0)
        {
            var size = 1;

            if (packet.GetActiveSize() < size)
                break;

            var cmd = (AuthCmd)packet.GetReadSpan()[0];

            if (cmd == AUTH_LOGON_CHALLENGE)
            {
                size = sizeof(LogonChallengeResponse_Header);

                if (packet.GetActiveSize() < size)
                    break;

                ref readonly var header = ref MemoryMarshal.AsRef<LogonChallengeResponse_Header>(packet.GetReadSpan());

                if (header.Result != WOW_SUCCESS)
                {
                    Console.WriteLine("[Authentication failed!]");
                    Console.WriteLine(AuthResultToStr(header.Result));
                    CloseSocket();
                    return;
                }

                size += sizeof(LogonChallengeResponse_Body);

                if (packet.GetActiveSize() < size)
                    break;

                ref readonly var body = ref MemoryMarshal.AsRef<LogonChallengeResponse_Body>(
                    packet.GetReadSpan().Slice(sizeof(LogonChallengeResponse_Header)));

                if ((body.SecurityFlags & 0x1) != 0)
                {
                    size += sizeof(LogonChallengeResponse_PIN);

                    if (packet.GetActiveSize() < size)
                        break;
                }
                if ((body.SecurityFlags & 0x2) != 0)
                {
                    size += sizeof(LogonChallengeResponse_Matrix);

                    if (packet.GetActiveSize() < size)
                        break;
                }
                if ((body.SecurityFlags & 0x4) != 0)
                {
                    size += sizeof(LogonChallengeResponse_Token);

                    if (packet.GetActiveSize() < size)
                        break;
                }

                if ((body.SecurityFlags & 0x1) != 0)
                {
                    int offset = sizeof(LogonChallengeResponse_Header) + sizeof(LogonChallengeResponse_Body);
                    ref readonly var pin = ref MemoryMarshal.AsRef<LogonChallengeResponse_PIN>(packet.GetReadSpan().Slice(offset));
                }

                if ((body.SecurityFlags & 0x2) != 0)
                {
                    int offset = sizeof(LogonChallengeResponse_Header) + sizeof(LogonChallengeResponse_Body);
                    if ((body.SecurityFlags & 0x1) != 0)
                        offset += sizeof(LogonChallengeResponse_PIN);

                    ref readonly var matrix = ref MemoryMarshal.AsRef<LogonChallengeResponse_Matrix>(packet.GetReadSpan().Slice(offset));
                }

                if ((body.SecurityFlags & 0x4) != 0)
                {
                    int offset = sizeof(LogonChallengeResponse_Header) + sizeof(LogonChallengeResponse_Body);
                    if ((body.SecurityFlags & 0x1) != 0)
                        offset += sizeof(LogonChallengeResponse_PIN);
                    if ((body.SecurityFlags & 0x2) != 0)
                        offset += sizeof(LogonChallengeResponse_Matrix);

                    ref readonly var token = ref MemoryMarshal.AsRef<LogonChallengeResponse_Token>(packet.GetReadSpan().Slice(offset));

                    Console.WriteLine("Has LogonChallengeResponse_Token");
                }

                fixed (byte* ptrB = body.B)
                fixed (byte* ptrg = body.g)
                fixed (byte* ptrN = body.N)
                fixed (byte* ptrSalt = body.Salt)
                {
                    _srp6.ProcessChallenge(
                        AccountName, AccountPassword,
                        new ReadOnlySpan<byte>(ptrN, body.N_length),
                        new ReadOnlySpan<byte>(ptrg, body.g_length),
                        new ReadOnlySpan<byte>(ptrB, 32),
                        new ReadOnlySpan<byte>(ptrSalt, 32));
                }

                Console.WriteLine("[SRP6] Calculated Client Key: {0}", Util.ByteArrayToHexStr(_srp6.GetClientK()));

                packet.ReadCompleted(size);

                SendLogonProof();
            }

            if (cmd == AUTH_LOGON_PROOF)
            {
                size = sizeof(LogonProofResponse_Header);

                if (packet.GetActiveSize() < size)
                    break;

                ref readonly var header = ref MemoryMarshal.AsRef<LogonProofResponse_Header>(packet.GetReadSpan());

                if (header.Result != WOW_SUCCESS)
                {
                    Console.WriteLine("=================================");
                    Console.WriteLine("Received A {0}", Util.ByteArrayToHexStr(_srp6.GetClientEphemeralA()));
                    Console.WriteLine("K {0}", Util.ByteArrayToHexStr(_srp6.GetClientK()));
                    Console.WriteLine("*===============================*");

                    Console.WriteLine(AuthResultToStr(header.Result));
                    CloseSocket();
                    return;
                }

                size += sizeof(LogonProofResponse_Body);

                if (packet.GetActiveSize() < size)
                    break;

                ref readonly var body = ref MemoryMarshal.AsRef<LogonProofResponse_Body>(
                    packet.GetReadSpan().Slice(sizeof(LogonProofResponse_Header)));

                fixed (void* m2Ptr = body.M2)
                {
                    if (!_srp6.IsValidM2(new ReadOnlySpan<byte>(m2Ptr, 20)))
                    {
                        Console.WriteLine("[Authentication failed!] M2 is invalid");
                        CloseSocket();
                        return;
                    }

                    Console.WriteLine("[Authentication Success] M2 is {0}", Util.ByteArrayToHexStr(_srp6.GetClientM2()));
                }

                packet.ReadCompleted(size);

                SendRealmlistRequest();
            }

            if (cmd == REALM_LIST)
            {
                size = sizeof(RealmlistResponse_Header);

                if (packet.GetActiveSize() < size)
                    break;

                ref readonly var header = ref MemoryMarshal.AsRef<RealmlistResponse_Header>(packet.GetReadSpan());

                if (header.Count == 0)
                {
                    Console.WriteLine("There are no realms!");
                    CloseSocket();
                    return;
                }

                size = 3 + header.Length;
                if (packet.GetActiveSize() < size)
                    break;

                ByteBuffer buffer = new(header.Length - sizeof(uint) - sizeof(ushort));
                var span = packet.GetReadSpan().Slice(sizeof(RealmlistResponse_Header));
                span.CopyTo(buffer.AsSpan());

                RealmList realmlist = new();
                realmlist.Populate(header.Count, buffer);
                realmlist.Print();

                packet.ReadCompleted(size);
            }
        }

        AsyncRead();
    }
}