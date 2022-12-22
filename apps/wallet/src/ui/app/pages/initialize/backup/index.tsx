// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import cl from 'classnames';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import Button from '_app/shared/button';
import CardLayout from '_app/shared/card-layout';
import { Text } from '_app/shared/text';
import { useLockedGuard } from '_app/wallet/hooks';
import Alert from '_components/alert';
import CopyToClipboard from '_components/copy-to-clipboard';
import Icon, { SuiIcons } from '_components/icon';
import Loading from '_components/loading';
import { useAppDispatch } from '_hooks';
import { loadEntropyFromKeyring } from '_redux/slices/account';
import { entropyToMnemonic, toEntropy } from '_shared/utils/bip39';

import st from './Backup.module.scss';

export type BackupPageProps = {
    mode?: 'created' | 'imported';
};

const BackupPage = ({ mode = 'created' }: BackupPageProps) => {
    const guardsLoading = useLockedGuard(false);
    const [loading, setLoading] = useState(true);
    const [mnemonic, setLocalMnemonic] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const navigate = useNavigate();
    const dispatch = useAppDispatch();
    useEffect(() => {
        (async () => {
            if (guardsLoading || mode !== 'created') {
                return;
            }
            setLoading(true);
            try {
                setLocalMnemonic(
                    entropyToMnemonic(
                        toEntropy(
                            await dispatch(loadEntropyFromKeyring({})).unwrap()
                        )
                    )
                );
            } catch (e) {
                setError(
                    (e as Error).message ||
                        'Something is wrong, Recovery Phrase is empty.'
                );
            } finally {
                setLoading(false);
            }
        })();
    }, [dispatch, mode, guardsLoading]);
    return (
        <Loading loading={guardsLoading}>
            <CardLayout
                icon="success"
                title={`Wallet ${
                    mode === 'imported' ? 'Imported' : 'Created'
                } Successfully!`}
                className="bg-aliceBlue"
            >
                {mode === 'created' ? (
                    <>
                        <div className="mb-1 mt-7.5">
                            <Text
                                variant="caption"
                                color="steel-darker"
                                weight="bold"
                            >
                                Recovery phrase
                            </Text>
                        </div>
                        <div className="mb-3.5 mt-2 text-center">
                            <Text
                                variant="p2"
                                color="steel-dark"
                                weight="normal"
                            >
                                Your recovery phrase makes it easy to back up
                                and restore your account.
                            </Text>
                        </div>
                        <Loading loading={loading}>
                            {mnemonic ? (
                                <div
                                    className={cl(
                                        st.mnemonic,
                                        'text-steel-dark'
                                    )}
                                >
                                    {mnemonic}
                                    <CopyToClipboard
                                        txt={mnemonic}
                                        className="mt-2.5 text-steel-dark text-subtitleSmall self-end cursor-pointer leading-100"
                                        mode="plain"
                                    >
                                        COPY
                                    </CopyToClipboard>
                                </div>
                            ) : (
                                <Alert>{error}</Alert>
                            )}
                        </Loading>
                        <div className="mt-3.75 mb-1 text-center">
                            <Text
                                variant="caption"
                                color="steel-dark"
                                weight="semibold"
                            >
                                WARNING
                            </Text>
                        </div>
                        <div className="mb-1 text-center">
                            <Text
                                variant="p2"
                                color="steel-dark"
                                weight="normal"
                            >
                                Never disclose your secret recovery phrase.
                                Anyone with the passphrase can take over your
                                account forever.
                            </Text>
                        </div>
                    </>
                ) : null}
                <div className={st.fill} />
                <Button
                    type="button"
                    className={st.btn}
                    size="large"
                    mode="primary"
                    onClick={() => navigate('/')}
                >
                    Open Sui Wallet
                    <Icon icon={SuiIcons.ArrowLeft} className={st.arrowUp} />
                </Button>
            </CardLayout>
        </Loading>
    );
};

export default BackupPage;
