/// <reference types="node" />
declare namespace Tea {

    export function teaDecrypt(v: Buffer, k: Buffer, iter: number): Buffer | undefined;

    export function teaEncrypt(v: Buffer, k: Buffer, iter: number): Buffer | undefined;

    export const TEA_BLOCK_LEN: number;
    export const TEA_KEY_LEN: number;

}

export = Tea;