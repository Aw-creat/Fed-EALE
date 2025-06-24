pragma circom 2.0.0;

include "D:/software/Node/node_global/node_modules/circomlib/circuits/pointbits.circom";
include "D:/software/Node/node_global/node_modules/circomlib/circuits/pedersen.circom";
include "D:/software/Node/node_global/node_modules/circomlib/circuits/compconstant.circom";
include "D:/software/Node/node_global/node_modules/circomlib/circuits/escalarmulany.circom";
include "D:/software/Node/node_global/node_modules/circomlib/circuits/escalarmulfix.circom";
include "D:/software/Node/node_global/node_modules/circomlib/circuits/sha256.circom";

template CombinedVerifier(levels) {
    // 输入信号定义
    signal input root[256];         // 根哈希值（同时作为签名验证的消息）
    signal input pubKey[256];       // 公钥
    signal input R8[256];           // 签名 R8 部分
    signal input S[256];            // 签名 S 部分
    signal input leaf[256];         // Merkle树叶节点
    signal input path[levels][256]; // Merkle路径
    signal output valid;            // 最终验证结果

    // 第一部分：EdDSA签名验证
    // 转换为曲线上的点的中间信号
    signal pubKeyX;    // 公钥 x 坐标
    signal pubKeyY;    // 公钥 y 坐标
    signal R8x;        // R8 点的 x 坐标
    signal R8y;        // R8 点的 y 坐标

    // 验证 S < 群的阶
    component sCheck = CompConstant(2736030358979909402780800718157159386076813972158567259200215660948447373040);
    for (var i = 0; i < 254; i++) {
        sCheck.in[i] <== S[i];
    }
    sCheck.out === 0;
    S[254] === 0;
    S[255] === 0;

    // 转换并验证公钥点
    component pubKeyToCurve = Bits2Point_Strict();
    for (var i = 0; i < 256; i++) {
        pubKeyToCurve.in[i] <== pubKey[i];
    }
    pubKeyX <== pubKeyToCurve.out[0];
    pubKeyY <== pubKeyToCurve.out[1];

    // 转换并验证 R8 点
    component r8ToCurve = Bits2Point_Strict();
    for (var i = 0; i < 256; i++) {
        r8ToCurve.in[i] <== R8[i];
    }
    R8x <== r8ToCurve.out[0];
    R8y <== r8ToCurve.out[1];

    // 计算哈希 h = H(R8, pubKey, root)
    component msgHash = Pedersen(768);
    for (var i = 0; i < 256; i++) {
        msgHash.in[i] <== R8[i];
        msgHash.in[256 + i] <== pubKey[i];
        msgHash.in[512 + i] <== root[i];
    }

    // 将哈希结果转换为比特数组
    component hashToBits = Point2Bits_Strict();
    hashToBits.in[0] <== msgHash.out[0];
    hashToBits.in[1] <== msgHash.out[1];

    // 计算 8*pubKey
    component double1 = BabyDbl();
    double1.x <== pubKeyX;
    double1.y <== pubKeyY;
    
    component double2 = BabyDbl();
    double2.x <== double1.xout;
    double2.y <== double1.yout;
    
    component double3 = BabyDbl();
    double3.x <== double2.xout;
    double3.y <== double2.yout;

    // 验证公钥不为零点
    component zeroCheck = IsZero();
    zeroCheck.in <== double3.x;
    zeroCheck.out === 0;

    // 计算 h * (8*pubKey)
    component scalarMul = EscalarMulAny(256);
    for (var i = 0; i < 256; i++) {
        scalarMul.e[i] <== hashToBits.out[i];
    }
    scalarMul.p[0] <== double3.xout;
    scalarMul.p[1] <== double3.yout;

    // 计算 R8 + h*(8*pubKey)
    component rightSide = BabyAdd();
    rightSide.x1 <== R8x;
    rightSide.y1 <== R8y;
    rightSide.x2 <== scalarMul.out[0];
    rightSide.y2 <== scalarMul.out[1];

    // 计算 S*B8
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    
    component leftSide = EscalarMulFix(256, BASE8);
    for (var i = 0; i < 256; i++) {
        leftSide.e[i] <== S[i];
    }

    // 验证：S*B8 == R8 + h*(8*pubKey)
    component signatureCheck1 = IsEqual();
    signatureCheck1.in[0] <== leftSide.out[0];
    signatureCheck1.in[1] <== rightSide.xout;
    
    component signatureCheck2 = IsEqual();
    signatureCheck2.in[0] <== leftSide.out[1];
    signatureCheck2.in[1] <== rightSide.yout;

    signal signatureValid;
    signatureValid <== signatureCheck1.out * signatureCheck2.out;

    // 第二部分：Merkle树验证
    // 用于存储计算过程中的哈希值
    component hashers[levels];
    signal intermediate[levels+1][256];

    // 初始值设为叶节点
    for (var i = 0; i < 256; i++) {
        intermediate[0][i] <== leaf[i];
    }

    // 计算路径上每一层的哈希值
    for (var i = 0; i < levels; i++) {
        hashers[i] = Sha256(512);
        
        for (var j = 0; j < 256; j++) {
            hashers[i].in[j] <== intermediate[i][j];
            hashers[i].in[256 + j] <== path[i][j];
        }
        
        for (var j = 0; j < 256; j++) {
            intermediate[i+1][j] <== hashers[i].out[j];
        }
    }

    // 验证最终计算得到的根哈希是否与输入的根哈希相同
    signal equalChecks[256];
    signal mulChecks[256];
    
    for (var i = 0; i < 256; i++) {
        equalChecks[i] <== intermediate[levels][i] - root[i];
        mulChecks[i] <== equalChecks[i] * equalChecks[i];
    }

    signal sum[256];
    sum[0] <== mulChecks[0];
    for (var i = 1; i < 256; i++) {
        sum[i] <== sum[i-1] + mulChecks[i];
    }

    signal merkleValid;
    merkleValid <== 1 - sum[255];

    // 最终验证结果：签名验证和Merkle验证都必须通过
    valid <== signatureValid * merkleValid;
}

component main = CombinedVerifier(4);