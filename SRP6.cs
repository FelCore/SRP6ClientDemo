using System.Numerics;

namespace SRP6ClientDemo;

public unsafe class SRP6
{
    public const int EPHEMERAL_KEY_LENGTH = 32;
    public const int SESSION_KEY_LENGTH = 40;

    /// <summary>
    /// Process SRP6 K, M1 and M2 from server challenge response.
    /// </summary>
    /// <param name="accountName">Account name</param>
    /// <param name="accountPassword">Account password</param>
    /// <param name="bN">Server modulus</param>
    /// <param name="bg">Server generator</param>
    /// <param name="bB">Server public ephemeral Key</param>
    /// <param name="bSalt">Server salt</param>
    public void ProcessChallenge(
        string accountName,
        string accountPassword,
        ReadOnlySpan<byte> bN,
        ReadOnlySpan<byte> bg,
        ReadOnlySpan<byte> bB,
        ReadOnlySpan<byte> bSalt)
    {
        _bA.AsSpan().Fill(0);
        _bK.AsSpan().Fill(0);
        _bM1.AsSpan().Fill(0);
        _bM2.AsSpan().Fill(0);

        var N = new BigInteger(bN, true);
        var g = new BigInteger(bg, true);
        var B = new BigInteger(bB, true);

        // Client secret
        var a = BigInteger.Zero;
        a.SetRandom(19 * 8);

        // Safeguards
        if (B.IsZero || (B % N).IsZero)
        {
            Console.WriteLine("SRP safeguard: B (mod N) was zero!");
            return;
        }

        if (a > N || a == N)
        {
            Console.WriteLine("SRP safeguard: a must be less than N!");
            return;
        }

        SHA1Hash h1 = new();
        SHA1Hash h2 = new();

        // I = H(g) xor H(N)

        SHA1Hash hg = h1;
        hg.UpdateData(bg);
        hg.Finish();

        SHA1Hash hN = h2;
        hN.UpdateData(bN);
        hN.Finish();

        // g hash ^ N hash
        Span<byte> gNHash = stackalloc byte[20];

        for (int i = 0; i < 20; i++)
            gNHash[i] = (byte)(hg.GetDigest()[i] ^ hN.GetDigest()[i]);

        // x = H(s, H(C, ":", P));

        SHA1Hash hCredentials = h1;
        hCredentials.Initialize();
        hCredentials.UpdateData((accountName + ":" + accountPassword).ToUpperInvariant());
        hCredentials.Finish();

        SHA1Hash hx = h2;
        hx.Initialize();
        hx.UpdateData(bSalt);
        hx.UpdateData(hCredentials.GetDigest());
        hx.Finish();

        // Client credentials

        var x = new BigInteger(hx.GetDigest(), true);

        // A

        var A = g.ModPow(a, N);
        A.TryWriteBytes(_bA, out var _, true);

        // u = H(A, B)

        SHA1Hash hu = h1;
        hu.Initialize();
        hu.UpdateData(_bA);
        hu.UpdateData(bB);
        hu.Finish();

        // Scrambling

        var u = new BigInteger(hu.GetDigest(), true);

        if (u.IsZero)
        {
            Console.WriteLine("SRP safeguard: 'u' must not be zero!");
            return;
        }

        // Multiplier
        var k = new BigInteger(3u);

        // S

        var S = ((B + k * (N - g.ModPow(x, N))) % N).ModPow(a + u * x, N);

        if (S.IsZero || S.Sign == -1)
        {
            Console.WriteLine("SRP safeguard: S must be greater than 0!");
            return;
        }

        // K

        Span<byte> SPart0 = stackalloc byte[16];
        Span<byte> SPart1 = stackalloc byte[16];

        Span<byte> sBytes = stackalloc byte[32];
        S.TryWriteBytes(sBytes, out var bytesWritten, true);

        for (int i = 0; i < 16; i++)
        {
            SPart0[i] = sBytes[i * 2];
            SPart1[i] = sBytes[i * 2 + 1];
        }

        SHA1Hash hEven = h1;
        hEven.Initialize();
        hEven.UpdateData(SPart0);
        hEven.Finish();

        SHA1Hash hOdd = h2;
        hOdd.Initialize();
        hOdd.UpdateData(SPart1);
        hOdd.Finish();

        for (int i = 0; i < 20; i++)
        {
            _bK[i * 2] = hEven.GetDigest()[i];
            _bK[i * 2 + 1] = hOdd.GetDigest()[i];
        }

        // M1 = H(I, H(C), s, A, B, K)

        SHA1Hash hUsername = h1;
        hUsername.Initialize();
        hUsername.UpdateData(accountName.ToUpper());
        hUsername.Finish();

        SHA1Hash hM1 = h2;
        hM1.Initialize();
        hM1.UpdateData(gNHash);
        hM1.UpdateData(hUsername.GetDigest());
        hM1.UpdateData(bSalt);
        hM1.UpdateData(_bA);
        hM1.UpdateData(bB);
        hM1.UpdateData(_bK);
        hM1.Finish();

        hM1.GetDigest(_bM1);

        // M2 = H(A, M1, K)

        SHA1Hash hM2 = h1;
        hM2.Initialize();
        hM2.UpdateData(_bA);
        hM2.UpdateData(hM1.GetDigest());
        hM2.UpdateData(_bK);
        hM2.Finish();

        hM2.GetDigest(_bM2);

        h1.Dispose();
        h2.Dispose();
    }

    public bool IsValidM2(ReadOnlySpan<byte> buffer)
    {
        return _bM2.AsSpan().SequenceEqual(buffer);
    }

    public ReadOnlySpan<byte> GetClientEphemeralA() { return _bA; }
    public ReadOnlySpan<byte> GetClientM1() { return _bM1; }
    public ReadOnlySpan<byte> GetClientM2() { return _bM2; }
    public ReadOnlySpan<byte> GetClientK() { return _bK; }

    byte[] _bA = new byte[EPHEMERAL_KEY_LENGTH]; // Client public
    byte[] _bK = new byte[SESSION_KEY_LENGTH]; // Key based on S
    byte[] _bM1 = new byte[SHA1Hash.SHA1_DIGEST_LENGTH]; // M1
    byte[] _bM2 = new byte[SHA1Hash.SHA1_DIGEST_LENGTH]; // M2
}
