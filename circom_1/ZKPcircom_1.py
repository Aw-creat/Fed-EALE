import subprocess
import os
import shutil
import urllib.request

def run_circom_pipeline():
    circuit_file = "./circom_1/circuit_6.circom"
    build_dir = "D:/software/Node/node_global/node_modules/circom/factor_t_4"
    input_file = "./circom_1/input.json"  # 你前面代码生成的
    witness_file = os.path.join(build_dir, "circuit_6_js/witness.wtns")

    # 你的本地 ptau 文件路径
    ptau_file = r"D:\software\Node\node_global\node_modules\circom\factor_t_4\pot19_final.ptau"

    # 输出文件路径
    zkey_file = os.path.join(build_dir, "circuit_6_js/circuit_6.zkey")
    proof_file = os.path.join(build_dir, "circuit_6_js/proof.json")
    public_file = os.path.join(build_dir, "circuit_6_js/public.json")
    vkey_file = os.path.join(build_dir, "circuit_6_js/verification_key.json")

    os.makedirs(build_dir, exist_ok=True)

    # Step 1: 编译电路
    print("Step 1: 编译电路...")
    subprocess.run([
        "circom", circuit_file,
        "--r1cs", "--wasm", "--sym",
        "-o", build_dir
    ], check=True)

    # Step 2: 生成 witness
    print("Step 2: 生成 witness...")
    subprocess.run([
        "node", os.path.join(build_dir, "circuit_6_js/generate_witness.js"),
        os.path.join(build_dir, "circuit_6_js/circuit_6.wasm"),
        input_file,
        witness_file
    ], check=True)

    # Step 3: 使用本地 ptau 文件（跳过下载）
    print("Step 3: 使用已有 ptau 文件")
    if not os.path.exists(ptau_file):
        raise FileNotFoundError(f"找不到 ptau 文件: {ptau_file}")

    # Step 4: 生成 proving/verifying key
    print("Step 4: 生成 proving/verifying keys...")
    subprocess.run([
        r"D:\software\Node\node_global\snarkjs.cmd", "groth16", "setup",
        os.path.join(build_dir, "circuit_6.r1cs"),
        ptau_file,
        zkey_file
    ], check=True)

    # Step 5: 生成 zk 证明
    print("Step 5: 生成 zk 证明...")
    subprocess.run([
        r"D:\software\Node\node_global\snarkjs.cmd", "groth16", "prove",
        zkey_file,
        witness_file,
        proof_file,
        public_file
    ], check=True)

    # Step 6: 验证 zk 证明
    print("Step 6: 验证 zk 证明...")
    subprocess.run([
        r"D:\software\Node\node_global\snarkjs.cmd", "zkey", "export", "verificationkey",
        zkey_file,
        vkey_file
    ], check=True)

    subprocess.run([
        r"D:\software\Node\node_global\snarkjs.cmd", "groth16", "verify",
        vkey_file,
        public_file,
        proof_file
    ], check=True)

    print("零知识证明验证成功！")


if __name__ == "__main__":
    run_circom_pipeline()
