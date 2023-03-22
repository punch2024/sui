// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
    PaginationFirst24,
    PaginationNext24,
    PaginationPrev24,
} from '@mysten/icons';
import { useState } from 'react';

export interface PaginationProps {
    hasPrev: boolean;
    hasNext: boolean;
    onFirst(): void;
    onPrev(): void;
    onNext(): void;
}

interface PaginationResponse {
    nextCursor: string | null;
    hasNextPage: boolean;
}

export function usePaginationStack() {
    const [stack, setStack] = useState<string[]>([]);

    return {
        cursor: stack.at(-1),
        props({
            hasNextPage = false,
            nextCursor = null,
        }: Partial<PaginationResponse> = {}): PaginationProps {
            return {
                hasPrev: stack.length > 0,
                hasNext: hasNextPage,
                onFirst() {
                    setStack([]);
                },
                onNext() {
                    if (nextCursor && hasNextPage) {
                        setStack((stack) => [...stack, nextCursor]);
                    }
                },
                onPrev() {
                    setStack((stack) => stack.slice(0, -1));
                },
            };
        },
    };
}

function PaginationButton({
    label,
    icon: Icon,
    disabled,
    onClick,
}: {
    label: string;
    icon: typeof PaginationFirst24;
    disabled: boolean;
    onClick(): void;
}) {
    return (
        <button
            className="rounded-md border border-steel px-2 py-1 text-steel shadow-xs disabled:border-gray-45 disabled:text-gray-45"
            aria-label={label}
            type="button"
            disabled={disabled}
            onClick={onClick}
        >
            <Icon className="text-[24px]" />
        </button>
    );
}

export function Pagination({
    hasNext,
    hasPrev,
    onFirst,
    onPrev,
    onNext,
}: PaginationProps) {
    return (
        <div className="flex gap-2">
            <PaginationButton
                label="Go to First"
                icon={PaginationFirst24}
                disabled={!hasPrev}
                onClick={onFirst}
            />
            <PaginationButton
                label="Previous"
                icon={PaginationPrev24}
                disabled={!hasPrev}
                onClick={onPrev}
            />
            <PaginationButton
                label="Next"
                icon={PaginationNext24}
                disabled={!hasNext}
                onClick={onNext}
            />
        </div>
    );
}
