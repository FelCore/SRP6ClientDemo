using System.Text;

namespace SRP6ClientDemo;
using static RealmFlags;

public enum RealmFlags : byte
{
    REALM_FLAG_NONE = 0x00,
    REALM_FLAG_INVALID = 0x01,
    REALM_FLAG_OFFLINE = 0x02,
    REALM_FLAG_SPECIFYBUILD = 0x04,
    REALM_FLAG_UNK1 = 0x08,
    REALM_FLAG_UNK2 = 0x10,
    REALM_FLAG_RECOMMENDED = 0x20,
    REALM_FLAG_NEW = 0x40,
    REALM_FLAG_FULL = 0x80
}

public struct Realm
{
    public byte Icon;
    public bool Lock;
    public RealmFlags Flags;
    public string Name;
    public string Address;
    public float Population;
    public byte Characters;
    public byte Timezone;
    public byte ID;
    public byte MajorVersion;
    public byte MinorVersion;
    public byte BugfixVersion;
    public ushort Build;
}

public class RealmList
{
    public void Populate(uint count, ByteBuffer buffer)
    {
        Array.Resize(ref _list, (int)count);

        for (uint i = 0; i < count; i++)
        {
            Realm realm = new();

            realm.Icon = buffer.Read<byte>();
            realm.Lock = buffer.Read<bool>();
            realm.Flags = buffer.Read<RealmFlags>();
            realm.Name = buffer.ReadString();
            realm.Address = buffer.ReadString();
            realm.Population = buffer.Read<float>();
            realm.Characters = buffer.Read<byte>();
            realm.Timezone = buffer.Read<byte>();
            realm.ID = buffer.Read<byte>();

            if ((realm.Flags & REALM_FLAG_SPECIFYBUILD) != 0)
            {
                realm.MajorVersion = buffer.Read<byte>();
                realm.MinorVersion = buffer.Read<byte>();
                realm.BugfixVersion = buffer.Read<byte>();
                realm.Build = buffer.Read<ushort>();
            }

            _list[i] = realm;
        }

        buffer.ReadSkip<byte>();
        buffer.ReadSkip<byte>();
    }

    public void Print()
    {
        Console.WriteLine("[Realmlist]");

        foreach (var realm in _list)
        {
            if ((realm.Flags & REALM_FLAG_SPECIFYBUILD) != 0)
            {
                //if (realm.MajorVersion != GameVersion[0] || realm.MinorVersion != GameVersion[1] || realm.BugfixVersion != GameVersion[2] || realm.Build != GameBuild)
                //    continue;
            }

            var sb = new StringBuilder();
            sb.Append(" - ");
            sb.Append(realm.Name);
            sb.Append(" [");
            sb.Append(realm.Address);
            sb.Append(" ] (");
            sb.Append(((realm.Flags & REALM_FLAG_OFFLINE) != 0 ? "Offline" : "Online"));
            sb.Append(")");

            Console.WriteLine(sb.ToString());
        }
    }

    //public Realm GetRealmByName(string name)
    //{

    //}

    Realm[] _list = Array.Empty<Realm>();
};