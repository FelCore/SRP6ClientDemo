using System.Numerics;

namespace SRP6ClientDemo;

public class SRP6
{
    public SRP6()
    {
        Reset();
    }

    public void Reset()
    {
        AccountName = "";
        AccountPassword = "";

        g = N = BigInteger.Zero;

        k = new BigInteger(3u);
        a.SetRandom(19 * 8);

        B = s = A = I = x = u = S = K = M1 = M2 = BigInteger.Zero;
    }

    public void SetCredentials(string name, string password)
    {
        AccountName = name.ToUpperInvariant();
        AccountPassword = password.ToUpperInvariant();
    }

    public void SetServerModulus(ReadOnlySpan<byte> buffer)
    {
        N = new BigInteger(buffer, true);
    }

    public void SetServerGenerator(ReadOnlySpan<byte> buffer)
    {
        g = new BigInteger(buffer, true);
    }

    public void SetServerEphemeralB(ReadOnlySpan<byte> buffer)
    {
        B = new BigInteger(buffer, true);
    }

    public void SetServerSalt(ReadOnlySpan<byte> buffer)
    {
        s = new BigInteger(buffer, true);
    }

    public void Calculate()
    {
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
        hg.UpdateData(g);
        hg.Finish();

        SHA1Hash hN = h2;
        hN.UpdateData(N);
        hN.Finish();

        Span<byte> bI = stackalloc byte[20];

        for (int i = 0; i < 20; i++)
            bI[i] = (byte)(hg.GetDigest()[i] ^ hN.GetDigest()[i]);

        I = new BigInteger(bI, true);

        // x = H(s, H(C, ":", P));

        SHA1Hash hCredentials = h1;
        hCredentials.Initialize();
        hCredentials.UpdateData(AccountName + ":" + AccountPassword);
        hCredentials.Finish();

        SHA1Hash hx = h2;
        hx.Initialize();
        hx.UpdateData(s);
        hx.UpdateData(hCredentials.GetDigest());
        hx.Finish();

        x = new BigInteger(hx.GetDigest(), true);

        // A

        A = g.ModPow(a, N);

        // u = H(A, B)

        SHA1Hash hu = h1;
        hu.Initialize();
        hu.UpdateData(A);
        hu.UpdateData(B);
        hu.Finish();

        u = new BigInteger(hu.GetDigest(), true);

        if (u.IsZero)
        {
            Console.WriteLine("SRP safeguard: 'u' must not be zero!");
            return;
        }

        // S

        S = ((B + k * (N - g.ModPow(x, N))) % N).ModPow(a + u * x, N);

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

        Span<byte> bK = stackalloc byte[40];

        for (int i = 0; i < 20; i++)
        {
            bK[i * 2] = hEven.GetDigest()[i];
            bK[i * 2 + 1] = hOdd.GetDigest()[i];
        }

        K = new BigInteger(bK, true);

        // M1 = H(I, H(C), s, A, B, K)

        SHA1Hash hUsername = h1;
        hUsername.Initialize();
        hUsername.UpdateData(AccountName);
        hUsername.Finish();

        SHA1Hash hM1 = h2;
        hM1.Initialize();
        hM1.UpdateData(I);
        hM1.UpdateData(hUsername.GetDigest());
        hM1.UpdateData(s);
        hM1.UpdateData(A);
        hM1.UpdateData(B);
        hM1.UpdateData(K);
        hM1.Finish();

        M1 = new BigInteger(hM1.GetDigest(), true);

        // M2 = H(A, M1, K)

        SHA1Hash hM2 = h1;
        hM2.Initialize();
        hM2.UpdateData(A);
        hM2.UpdateData(M1);
        hM2.UpdateData(K);
        hM2.Finish();

        M2 = new BigInteger(hM2.GetDigest(), true);

        h1.Dispose();
        h2.Dispose();
    }

    public bool IsValidM2(ReadOnlySpan<byte> buffer)
    {
        return M2 == new BigInteger(buffer, true);
    }

    public ref BigInteger GetClientEphemeralA() { return ref A; }
    public ref BigInteger GetClientM1() { return ref M1; }
    public ref BigInteger GetClientM2() { return ref M2; }
    public ref BigInteger GetClientK() { return ref K; }

    string AccountName = "";
    string AccountPassword = "";

    BigInteger N; // Modulus
    BigInteger g; // Generator
    BigInteger k; // Multiplier
    BigInteger B; // Server public
    BigInteger s; // Server salt
    BigInteger a; // Client secret
    BigInteger A; // Client public
    BigInteger I; // g hash ^ N hash
    BigInteger x; // Client credentials
    BigInteger u; // Scrambling
    BigInteger S; // Key
    BigInteger K; // Key based on S
    BigInteger M1; // M1
    BigInteger M2; // M2
}
