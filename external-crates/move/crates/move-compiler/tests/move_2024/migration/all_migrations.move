module a::m {

    friend a::n;

    struct S { f: u64 }

    struct LongerName {
        f: u64,
        x: S,
    }

    struct Positional(u64, u64, u64)

    fun t0(x: u64, s: S): u64 {
        let S { f: fin } = s;
        fin = 10;
        x = 20;
        fin + x
    }

    public(friend) fun t1() {}

}

module a::n {}
