using System.Text;

namespace SRP6ClientDemo;

public static class Util
{
    public static string ByteArrayToHexStr(ReadOnlySpan<byte> bytes, bool reverse = false)
    {
        int arrayLen = bytes.Length;
        int init = 0;
        int end = arrayLen;
        sbyte op = 1;

        if (reverse)
        {
            init = arrayLen - 1;
            end = -1;
            op = -1;
        }

        var sb = new StringBuilder(arrayLen * 2);

        for (int i = init; i != end; i += op)
            sb.Append(bytes[i].ToString("X2"));

        return sb.ToString();
    }
}
