// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useCurrentAccount, useSuiClientInfiniteQuery } from "@mysten/dapp-kit";
import { SuiObjectDisplay } from "@/components/SuiObjectDisplay";
import { Button } from "@radix-ui/themes";
import { LockClosedIcon } from "@radix-ui/react-icons";
import { InfiniteScrollArea } from "@/components/InfiniteScrollArea";
import { useLockObjectMutation } from "@/mutations/locked";

export function LockOwnedObjects() {
  const account = useCurrentAccount();

  const { mutate: lockObjectMutation, isPending } = useLockObjectMutation();

  const { data, fetchNextPage, isFetchingNextPage, hasNextPage, refetch } =
    useSuiClientInfiniteQuery(
      "getOwnedObjects",
      {
        owner: account?.address!,
        options: {
          showDisplay: true,
          showType: true,
        },
      },
      {
        enabled: !!account,
        select: (data) =>
          data.pages
            .flatMap((page) => page.data)
            .filter(
              (x) => !!x.data?.display && !!x.data?.display?.data?.image_url,
            ),
      },
    );

  return (
    <InfiniteScrollArea
      loadMore={() => fetchNextPage()}
      hasNextPage={hasNextPage}
      loading={isFetchingNextPage}
    >
      {data?.map((obj) => (
        <SuiObjectDisplay object={obj.data!}>
          <div className="text-right flex items-center justify-between">
            <p className="text-sm">
              Lock the item so it can be used for escrows.
            </p>
            <Button
              className="cursor-pointer"
              disabled={isPending}
              onClick={() => {
                lockObjectMutation(
                  { object: obj.data! },
                  {
                    onSuccess: () => refetch(),
                  },
                );
              }}
            >
              <LockClosedIcon />
              Lock Item
            </Button>
          </div>
        </SuiObjectDisplay>
      ))}
    </InfiniteScrollArea>
  );
}
