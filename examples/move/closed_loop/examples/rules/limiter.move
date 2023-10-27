// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0


// get_object({ id }) -> TokenPolicy<Token<LOL>>;
// transfer() -> TokenPolicy.transferRules[ "0x0::limiter::Limiter", "0x0::denomination::Denomination" ];

// do I know limiter? no -> abort
// do I know denomination? no -> abort

// let action = transfer();
// limiter::verify(policy, action);
// denomination::verify(policy, action);
// closed_loop::confirm_request(policy, request);

/// An example of a Rule for the Closed Loop Token which limits the amount per
/// operation.
module examples::limiter_rule {
    use std::string::String;
    use sui::tx_context::TxContext;
    use closed_loop::closed_loop::{
        Self as cl,
        TokenPolicy,
        TokenPolicyCap,
        ActionRequest
    };

    /// Trying to perform an action that exceeds the limit.
    const ELimitExceeded: u64 = 0;

    /// The Rule witness.
    struct Limiter has drop {}

    /// Configuration for the Rule.
    struct Config has store, drop {
        /// A limit for a single operation.
        limit: u64
    }

    /// Adds a limiter rule to the `TokenPolicy` with the given limit per
    /// operation.
    public fun add_for<T>(
        policy: &mut TokenPolicy<T>,
        cap: &TokenPolicyCap<T>,
        action: String,
        limit: u64,
        ctx: &mut TxContext
    ) {
        cl::add_rule_for_action(
            Limiter {}, policy, cap, action, Config { limit }, ctx
        );
    }

    /// Verifies that the request does not exceed the limit and adds an approval
    /// to the `ActionRequest`.
    public fun verify<T>(
        policy: &TokenPolicy<T>,
        request: &mut ActionRequest<T>,
        ctx: &mut TxContext
    ) {
        let config: &Config = cl::get_rule(
            Limiter {}, policy, cl::name(request)
        );

        assert!(cl::amount(request) <= config.limit, ELimitExceeded);

        cl::add_approval(Limiter {}, request, ctx);
    }

    ///
    public fun remove_for<T>(
        policy: &mut TokenPolicy<T>,
        cap: &TokenPolicyCap<T>,
        action: String,
        ctx: &mut TxContext
    ) {
        let _: Config = cl::remove_rule_for_action<T, Limiter, Config>(
            policy, cap, action, ctx
        );
    }
}

#[test_only]
module examples::limiter_rule_tests {
    use examples::limiter_rule as limiter;
    use std::string::utf8;
    use std::option::{none, /* some */};
    use closed_loop::closed_loop as cl;
    use closed_loop::closed_loop_tests as test;

    #[test]
    fun add_limiter_default() {
        let ctx = &mut sui::tx_context::dummy();
        let (policy, cap) = test::get_policy(ctx);

        limiter::add_for(&mut policy, &cap, utf8(b"action"), 100, ctx);

        let request = cl::new_request(utf8(b"action"), 100, none(), none(), ctx);

        limiter::verify(&policy, &mut request, ctx);

        // try to confirm request with 100 tokens
        cl::confirm_request(
            &mut policy,
            request,
            ctx
        );

        test::return_policy(policy, cap);
    }

    #[test]
    fun add_remove_limiter() {
        let ctx = &mut sui::tx_context::dummy();
        let (policy, cap) = test::get_policy(ctx);

        // adding limiter - confirmation required
        limiter::add_for(&mut policy, &cap, utf8(b"action"), 100, ctx);
        {
            let request = cl::new_request(utf8(b"action"), 100, none(), none(), ctx);
            limiter::verify(&policy, &mut request, ctx);
            cl::confirm_request(&mut policy, request, ctx);
        };

        // limiter removed - no confirmation required
        limiter::remove_for(&mut policy, &cap, utf8(b"action"), ctx);
        {
            let request = cl::new_request(utf8(b"action"), 100, none(), none(), ctx);
            cl::confirm_request(&mut policy, request, ctx);
        };

        // adding again to make sure the config was removed and can be re-added.
        limiter::add_for(&mut policy, &cap, utf8(b"action"), 100, ctx);
        {
            let request = cl::new_request(utf8(b"action"), 100, none(), none(), ctx);
            limiter::verify(&policy, &mut request, ctx);
            cl::confirm_request(&mut policy, request, ctx);
        };

        test::return_policy(policy, cap);
    }

    #[test, expected_failure(abort_code = examples::limiter_rule::ELimitExceeded)]
    fun add_limiter_limit_exceeded_fail() {
        let ctx = &mut sui::tx_context::dummy();
        let (policy, cap) = test::get_policy(ctx);

        limiter::add_for(&mut policy, &cap, utf8(b"action"), 100, ctx);

        let request = cl::new_request(utf8(b"action"), 101, none(), none(), ctx);
        limiter::verify(&policy, &mut request, ctx);

        abort 1337
    }
}
