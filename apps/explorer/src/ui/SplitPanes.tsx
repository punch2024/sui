// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ChevronLeft16, ChevronUp16 } from '@mysten/icons';
import clsx from 'clsx';
import { type ReactNode, useRef, useState } from 'react';
import {
    type Direction,
    type ImperativePanelHandle,
    Panel,
    PanelGroup,
    type PanelGroupProps,
    type PanelProps,
    PanelResizeHandle,
} from 'react-resizable-panels';

interface ResizeHandleProps {
    isHorizontal: boolean;
    isCollapsed: boolean;
    togglePanelCollapse: () => void;
    collapsibleButton?: boolean;
}

function ResizeHandle({
    isHorizontal,
    isCollapsed,
    collapsibleButton,
    togglePanelCollapse,
}: ResizeHandleProps) {
    const [isDragging, setIsDragging] = useState(false);

    const ChevronButton = isHorizontal ? ChevronLeft16 : ChevronUp16;

    return (
        <PanelResizeHandle
            className={clsx('group', isHorizontal ? 'px-2' : 'py-2')}
            onDragging={setIsDragging}
        >
            <div
                data-is-dragging={isDragging}
                className={clsx(
                    'relative bg-gray-45 group-hover:bg-sui data-[is-dragging=true]:bg-hero',
                    isHorizontal ? 'h-full w-px' : 'h-px'
                )}
            >
                {collapsibleButton && (
                    <button
                        type="button"
                        onClick={togglePanelCollapse}
                        data-is-dragging={isDragging}
                        className={clsx([
                            'flex cursor-pointer items-center rounded-full',
                            'border border-gray-45 bg-white text-gray-70',
                            'hover:bg-sui hover:text-white group-hover:block',
                            isCollapsed ? 'block' : 'hidden',
                            isHorizontal
                                ? 'absolute left-1/2 top-[5%] -translate-x-2/4'
                                : 'absolute left-[5%] top-1/2 -translate-y-2/4',
                        ])}
                    >
                        <ChevronButton
                            height={16}
                            width={16}
                            className={clsx(isCollapsed && 'rotate-180')}
                        />
                    </button>
                )}
            </div>
        </PanelResizeHandle>
    );
}

interface SplitPanelProps extends PanelProps {
    panel: ReactNode;
    direction: Direction;
    renderResizeHandle: boolean;
    collapsibleButton?: boolean;
}

function SplitPanel({
    panel,
    direction,
    renderResizeHandle,
    collapsibleButton,
    ...props
}: SplitPanelProps) {
    const ref = useRef<ImperativePanelHandle>(null);
    const [isCollapsed, setIsCollapsed] = useState(false);

    const togglePanelCollapse = () => {
        const panel = ref.current;
        if (panel) {
            if (isCollapsed) {
                panel.expand();
            } else {
                panel.collapse();
            }
        }
    };

    return (
        <>
            <Panel {...props} ref={ref} onCollapse={setIsCollapsed}>
                {panel}
            </Panel>
            {renderResizeHandle && (
                <ResizeHandle
                    isHorizontal={direction === 'horizontal'}
                    togglePanelCollapse={togglePanelCollapse}
                    isCollapsed={isCollapsed}
                    collapsibleButton={collapsibleButton}
                />
            )}
        </>
    );
}

export interface SplitPanesProps extends PanelGroupProps {
    panels: ReactNode[];
    collapsible?: boolean;
    collapsibleButtons?: boolean[];
    minSizes?: number[];
    defaultSizes?: number[];
}

export function SplitPanes({
    panels,
    collapsible,
    collapsibleButtons = [],
    minSizes = [],
    defaultSizes = [],
    ...props
}: SplitPanesProps) {
    const { direction } = props;

    return (
        <PanelGroup {...props}>
            {panels.map((panel, index) => (
                <SplitPanel
                    key={index}
                    panel={panel}
                    direction={direction}
                    collapsible={collapsible}
                    order={index}
                    minSize={minSizes[index]}
                    defaultSize={defaultSizes[index]}
                    collapsibleButton={collapsible && collapsibleButtons[index]}
                    renderResizeHandle={index < panels.length - 1}
                />
            ))}
        </PanelGroup>
    );
}
