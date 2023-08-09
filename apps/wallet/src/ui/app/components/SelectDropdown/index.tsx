// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ChevronDown12 } from '@mysten/icons';
import * as Select from '@radix-ui/react-select';
import { Text } from '_app/shared/text';

export interface SelectDropdownProps {
	placeholder?: string;
	dropdownOptions?: string[];
	onValueChange?: (value: string) => void;
	value?: string;
	offset?: number;
}

export function SelectDropdown({
	placeholder,
	dropdownOptions,
	onValueChange,
	value,
	offset,
}: SelectDropdownProps) {
	return (
		<div className="z-5 h-full">
			<Select.Root onValueChange={onValueChange} value={value}>
				<Select.Trigger
					className="flex items-center border border-solid border-gray-45 shadow-sm rounded-2lg bg-white px-4 py-2 gap-1.5 focus:outline-none h-full"
					aria-label="Food"
				>
					<Select.Value>
						<Text variant="body" weight="semibold" color="steel">
							{value || placeholder}
						</Text>
					</Select.Value>
					<Select.Icon className="flex items-center">
						<ChevronDown12 className="text-steel" />
					</Select.Icon>
				</Select.Trigger>
				<Select.Portal>
					<Select.Content
						className="z-10 min-w-[100px] bg-transparent"
						position="popper"
						side="bottom"
						sideOffset={offset}
						align="end"
					>
						<Select.Viewport className="bg-white p-2 border border-solid border-gray-45 rounded-md shadow-md">
							{dropdownOptions?.map((option) => {
								return (
									<Select.Item
										value={option}
										className="flex items-center hover:border-none hover:outline-none hover:cursor-pointer w-full hover:bg-hero-darkest hover:bg-opacity-5 p-2 rounded-sm"
									>
										<Select.ItemText>
											<Text variant="body" weight="semibold" color="steel">
												{option}
											</Text>
										</Select.ItemText>
									</Select.Item>
								);
							})}
						</Select.Viewport>
					</Select.Content>
				</Select.Portal>
			</Select.Root>
		</div>
	);
}
