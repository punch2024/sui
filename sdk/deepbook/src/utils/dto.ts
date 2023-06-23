export type Pool = {
    clob_v2: string;
    type: string;
    priceDecimals: number;
    amountDecimals: number;
    tickSize: number;
};

export type PoolInfo = {
    needChange: boolean;
    clob_v2: string;
    type: string;
    tickSize: number;
};

export type Records = {
    pools: Pool[];
    tokens: Token[];
    caps: Cap[];
};

export type Token = {
    symbol: string;
    type: string;
    decimals: number;
};

export type Cap = {
    owner: string;
    cap: string;
};
