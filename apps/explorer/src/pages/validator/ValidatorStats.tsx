// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useMemo } from 'react';

import { apyCalc } from '../validator/ApyCalulator';
import { DelegationAmount } from './DelegationAmount';

import type { ActiveValidator } from '~/pages/validator/ValidatorDataTypes';

import { Card } from '~/ui/Card';
import { Heading } from '~/ui/Heading';
import { Stats } from '~/ui/Stats';
import { getStakedPercent } from '~/utils/getStakedPercent';

type StatsCardProps = {
    validatorData: ActiveValidator;
    totalValidatorStake: string;
    epoch: number | string;
};

export function ValidatorStats({
    validatorData,
    epoch,
    totalValidatorStake,
}: StatsCardProps) {
    // TODO: add missing fields
    // const numberOfDelegators = 0;
    //  const selfStake = 0;
    //  const lastEpoch = 0;
    //  const totalRewards =  0;
    //  const networkStakingParticipation = 0;
    //  const votedLastRound =  0;
    //  const tallyingScore =  0;
    //  const lastNarwhalRound = 0;

    const apy = useMemo(
        () => apyCalc(validatorData, +epoch),
        [validatorData, epoch]
    );

    const totalStake = validatorData.fields.stake_amount;
    const delegatedStakePercentage = useMemo(
        () =>
            getStakedPercent(
                BigInt(validatorData.fields.stake_amount),
                BigInt(totalValidatorStake)
            ),
        [validatorData, totalValidatorStake]
    );

    return (
        <div className="flex w-full flex-col gap-5 md:mt-8 md:flex-row lg:basis-10/12">
            <div className=" basis-full md:basis-2/5">
                <Card spacing="lg">
                    <div className="flex max-w-full flex-col flex-nowrap gap-8">
                        <Heading
                            as="div"
                            variant="heading4/semibold"
                            color="steel-darker"
                        >
                            SUI Staked on Validator
                        </Heading>
                        <div className="flex flex-col flex-nowrap gap-8 lg:flex-row">
                            <Stats label="Staking APY" tooltip="Coming soon">
                                <Heading
                                    as="h3"
                                    variant="heading2/semibold"
                                    color="steel-darker"
                                >
                                    {apy > 0 ? `${apy}%` : '--'}
                                </Heading>
                            </Stats>
                            <Stats label="Total Staked" tooltip="Coming soon">
                                <DelegationAmount amount={totalStake} isStats />
                            </Stats>
                        </div>
                        <div className="flex flex-col flex-nowrap gap-8 lg:flex-row">
                            <Stats label="Delegators" tooltip="Coming soon">
                                <Heading
                                    as="h3"
                                    variant="heading3/semibold"
                                    color="steel-darker"
                                >
                                    --
                                </Heading>
                            </Stats>
                            <Stats
                                label="Delegated Staked"
                                tooltip="Coming soon"
                            >
                                <Heading
                                    as="h3"
                                    variant="heading3/semibold"
                                    color="steel-darker"
                                >
                                    {delegatedStakePercentage}%
                                </Heading>
                            </Stats>
                            <Stats label="Self Staked" tooltip="Coming soon">
                                <Heading
                                    as="h3"
                                    variant="heading3/semibold"
                                    color="steel-darker"
                                >
                                    --
                                </Heading>
                            </Stats>
                        </div>
                    </div>
                </Card>
            </div>
            <div className="basis-full md:basis-1/4">
                <Card spacing="lg">
                    <div className="flex max-w-full flex-col flex-nowrap gap-8">
                        <Heading
                            as="div"
                            variant="heading4/semibold"
                            color="steel-darker"
                        >
                            Validator Staking Rewards
                        </Heading>
                        <div className="flex flex-col flex-nowrap gap-8">
                            <Stats label="Last Epoch" tooltip="Coming soon">
                                <Heading
                                    as="h3"
                                    variant="heading3/semibold"
                                    color="steel-darker"
                                >
                                    --
                                </Heading>
                            </Stats>
                            <Stats label="Total Reward" tooltip="Coming soon">
                                <Heading
                                    as="h3"
                                    variant="heading3/semibold"
                                    color="steel-darker"
                                >
                                    --
                                </Heading>
                            </Stats>
                        </div>
                    </div>
                </Card>
            </div>
            <div className="basis-full md:basis-1/3">
                <Card spacing="lg">
                    <div className="flex  max-w-full flex-col flex-nowrap gap-8">
                        <Heading
                            as="div"
                            variant="heading4/semibold"
                            color="steel-darker"
                        >
                            Network Participation
                        </Heading>
                        <div className="flex flex-col flex-nowrap gap-8">
                            <div className="flex flex-col flex-nowrap gap-8 md:flex-row">
                                <Stats
                                    label="Staking Participation"
                                    tooltip="Coming soon"
                                >
                                    <Heading
                                        as="h3"
                                        variant="heading3/semibold"
                                        color="steel-darker"
                                    >
                                        --
                                    </Heading>
                                </Stats>

                                <Stats
                                    label="voted Last Round"
                                    tooltip="Coming soon"
                                >
                                    <Heading
                                        as="h3"
                                        variant="heading3/semibold"
                                        color="steel-darker"
                                    >
                                        --
                                    </Heading>
                                </Stats>
                            </div>
                            <div className="flex flex-col flex-nowrap gap-8 md:flex-row">
                                <Stats
                                    label="Tallying Score"
                                    tooltip="Coming soon"
                                >
                                    <Heading
                                        as="h3"
                                        variant="heading3/semibold"
                                        color="steel-darker"
                                    >
                                        --
                                    </Heading>
                                </Stats>

                                <Stats
                                    label="Last Narwhal Round"
                                    tooltip="Coming soon"
                                >
                                    <Heading
                                        as="h3"
                                        variant="heading3/semibold"
                                        color="steel-darker"
                                    >
                                        --
                                    </Heading>
                                </Stats>
                            </div>
                        </div>
                    </div>
                </Card>
            </div>
        </div>
    );
}
