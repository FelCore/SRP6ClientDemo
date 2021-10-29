using System.Numerics;

namespace SRP6ClientDemo;

public static class Extensions
{
    public static void SetRandom(ref this BigInteger num, int bits)
    {
        if (bits < 8 || bits % 8 != 0)
            throw new ArgumentException("Value of parameter bits must be multiplier of 8!");

        int byteCount = bits / 8;

        Span<byte> buffer = stackalloc byte[byteCount];
        // Make the MSB be 1
        buffer[byteCount - 1] = (byte)(128 + Random.Shared.Next(128));

        Random.Shared.NextBytes(buffer.Slice(0, byteCount - 1));

        num = new BigInteger(buffer, true);
    }

    public static BigInteger ModPow(this BigInteger value, BigInteger exponent, BigInteger modulus)
    {
        return BigInteger.ModPow(value, exponent, modulus);
    }
}
