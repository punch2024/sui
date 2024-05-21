module 0x42::M {
    const ERROR_NUM: u64 = 2;
    
    #[allow(lint(combinable_comparison))]
    public fun func1(x: u64, y: u64) {
        if (x < y || x == y) {}; // should be x <= y
    }
}