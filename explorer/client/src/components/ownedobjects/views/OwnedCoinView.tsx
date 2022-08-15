// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Coin } from '@mysten/sui.js';
import React, { useCallback, useEffect, useState } from 'react';

import { ReactComponent as ContentIcon } from '../../../assets/SVGIcons/closed-content.svg';
import { handleCoinType } from '../../../utils/stringUtils';
import Longtext from '../../longtext/Longtext';
import Pagination from '../../pagination/Pagination';
import { type DataType, ITEMS_PER_PAGE } from '../OwnedObjectConstants';

import styles from '../styles/OwnedCoin.module.css';

export default function OwnedCoinView({ results }: { results: DataType }) {
    const CLOSED_TYPE_STRING = '';

    const [openedType, setOpenedType] = useState(CLOSED_TYPE_STRING);

    const [currentPage, setCurrentPage] = useState(1);

    const openThisType = useCallback(
        (thisType: string) => () => {
            setOpenedType(thisType);
        },
        []
    );

    const goBack = useCallback(() => setOpenedType(CLOSED_TYPE_STRING), []);

    const uniqueTypes = Array.from(new Set(results.map(({ Type }) => Type)));

    // Switching the page closes any open group:
    useEffect(() => {
        setOpenedType(CLOSED_TYPE_STRING);
    }, [currentPage]);

    return (
        <>
            <div id="groupCollection" className={styles.groupview}>
                <div className={styles.firstrow}>
                    <div>Type</div>
                    <div>Objects</div>
                    <div>Balance</div>
                </div>
                <div className={styles.body}>
                    {uniqueTypes
                        .slice(
                            (currentPage - 1) * ITEMS_PER_PAGE,
                            currentPage * ITEMS_PER_PAGE
                        )
                        .map((typeV) => {
                            const subObjList = results.filter(
                                ({ Type }) => Type === typeV
                            );
                            return (
                                <div
                                    key={typeV}
                                    className={
                                        openedType === typeV
                                            ? styles.openedgroup
                                            : styles.closedgroup
                                    }
                                >
                                    <div
                                        onClick={
                                            openedType === typeV
                                                ? goBack
                                                : openThisType(typeV)
                                        }
                                        className={styles.summary}
                                    >
                                        <div
                                            className={
                                                openedType === typeV
                                                    ? styles.openicon
                                                    : styles.closedicon
                                            }
                                        >
                                            <ContentIcon />
                                        </div>
                                        <div>{handleCoinType(typeV)}</div>
                                        <div>{subObjList.length}</div>
                                        <div>
                                            {subObjList[0]._isCoin &&
                                            subObjList.every(
                                                (el) => el.balance !== undefined
                                            )
                                                ? `${subObjList.reduce(
                                                      (prev, current) =>
                                                          prev.add(
                                                              current.balance!
                                                          ),
                                                      Coin.getZero()
                                                  )}`
                                                : ''}
                                        </div>
                                        <div />
                                    </div>
                                    <div className={styles.openbody}>
                                        {openedType === typeV &&
                                            subObjList.map((subObj, index) => (
                                                <React.Fragment key={index}>
                                                    <div
                                                        className={
                                                            styles.objectid
                                                        }
                                                    >
                                                        <div />
                                                        <div>Object ID</div>
                                                        <div>
                                                            <Longtext
                                                                text={subObj.id}
                                                                category="objects"
                                                                isCopyButton={
                                                                    false
                                                                }
                                                            />
                                                        </div>
                                                        <div />
                                                    </div>
                                                    <div
                                                        className={
                                                            styles.balance
                                                        }
                                                    >
                                                        <div />
                                                        <div>Balance</div>
                                                        <div>
                                                            {subObj.balance?.toString()}
                                                        </div>
                                                        <div />
                                                    </div>
                                                </React.Fragment>
                                            ))}
                                    </div>
                                </div>
                            );
                        })}
                </div>
            </div>
            <Pagination
                totalItems={uniqueTypes.length}
                itemsPerPage={ITEMS_PER_PAGE}
                currentPage={currentPage}
                onPagiChangeFn={setCurrentPage}
            />
        </>
    );
}
