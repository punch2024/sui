/// A Bag is a heterogeneous collection of objects with arbitrary types, i.e.
/// the objects in the bag don't need to be of the same type.
/// These objects are not stored in the Bag directly, instead only a reference
/// to their IDs are stored as a proof of ownership. Sui tracks the ownership
/// and is aware that the Bag owns those objects in it. Only the owner of the Bag
/// could mutate the objects in the Bag.
/// Bag is different from the Collection type in that Collection
/// only supports owning objects of the same type.
module Sui::Bag {
    use Std::Errors;
    use Std::Option::{Self, Option};
    use Std::Vector::Self;
    use Sui::ID::{Self, ID, VersionedID};
    use Sui::Transfer;
    use Sui::TxContext::{Self, TxContext};

    // Error codes
    /// When removing an object from the collection, EOBJECT_NOT_FOUND
    /// will be triggered if the object is not owned by the collection.
    const EOBJECT_NOT_FOUND: u64 = 0;

    /// Adding the same object to the collection twice is not allowed.
    const EOBJECT_DOUBLE_ADD: u64 = 1;

    /// The max capacity set for the collection cannot exceed the hard limit
    /// which is DEFAULT_MAX_CAPACITY.
    const EINVALID_MAX_CAPACITY: u64 = 2;

    /// Trying to add object to the collection when the collection is
    /// already at its maximum capacity.
    const EMAX_CAPACITY_EXCEEDED: u64 = 3;

    // TODO: this is a placeholder number
    const DEFAULT_MAX_CAPACITY: u64 = 65536;

    struct Bag has key {
        id: VersionedID,
        objects: vector<ID>,
        max_capacity: u64,
    }

    /// Create a new Bag and return it.
    public fun new(ctx: &mut TxContext): Bag {
        new_with_max_capacity(ctx, DEFAULT_MAX_CAPACITY)
    }

    /// Create a new Bag with custom size limit and return it.
    public fun new_with_max_capacity(ctx: &mut TxContext, max_capacity: u64): Bag {
        assert!(
            max_capacity <= DEFAULT_MAX_CAPACITY && max_capacity > 0 ,
            Errors::limit_exceeded(EINVALID_MAX_CAPACITY)
        );
        Bag {
            id: TxContext::new_id(ctx),
            objects: Vector::empty(),
            max_capacity,
        }
    }

    /// Create a new Bag and transfer it to the signer.
    public fun create(ctx: &mut TxContext) {
        Transfer::transfer(new(ctx), TxContext::sender(ctx))
    }

    /// Returns the size of the Bag.
    public fun size(c: &Bag): u64 {
        Vector::length(&c.objects)
    }

    /// Add a new object to the Bag.
    /// Abort if the object is already in the Bag.
    public fun add<T: key>(c: &mut Bag, object: T) {
        assert!(
            size(c) + 1 <= c.max_capacity,
            Errors::limit_exceeded(EMAX_CAPACITY_EXCEEDED)
        );
        let id = ID::id(&object);
        if (contains(c, id)) {
            abort EOBJECT_DOUBLE_ADD
        };
        Vector::push_back(&mut c.objects, *id);
        Transfer::transfer_to_object_unsafe(object, c);
    }

    /// Check whether the Bag contains a specific object,
    /// identified by the object id in bytes.
    public fun contains(c: &Bag, id: &ID): bool {
        Option::is_some(&find(c, id))
    }

    /// Remove and return the object from the Bag.
    /// Abort if the object is not found.
    public fun remove<T: key>(c: &mut Bag, object: T): T {
        let idx = find(c, ID::id(&object));
        if (Option::is_none(&idx)) {
            abort EOBJECT_NOT_FOUND
        };
        Vector::remove(&mut c.objects, *Option::borrow(&idx));
        object
    }

    /// Remove the object from the Bag, and then transfer it to the signer.
    public fun remove_and_take<T: key>(c: &mut Bag, object: T, ctx: &mut TxContext) {
        let object = remove(c, object);
        Transfer::transfer(object, TxContext::sender(ctx));
    }

    /// Transfer the entire Bag to `recipient`.
    public fun transfer(c: Bag, recipient: address, _ctx: &mut TxContext) {
        Transfer::transfer(c, recipient)
    }

    /// Look for the object identified by `id_bytes` in the Bag.
    /// Returns the index if found, none if not found.
    fun find(c: &Bag, id: &ID): Option<u64> {
        let i = 0;
        let len = size(c);
        while (i < len) {
            if (Vector::borrow(&c.objects, i) == id) {
                return Option::some(i)
            };
            i = i + 1;
        };
        return Option::none()
    }
}
