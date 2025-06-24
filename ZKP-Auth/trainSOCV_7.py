import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, random_split
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import os
from typing import List, Dict, Tuple
import json

# 设置随机种子
torch.manual_seed(42)
if torch.cuda.is_available():
    torch.cuda.manual_seed(42)

# 设备配置
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 创建输出目录
OUTPUT_DIR = "D:/wp123/Code/python/FL-AELE/output_7"
os.makedirs(OUTPUT_DIR, exist_ok=True)


class SOCDataset(Dataset):
    def __init__(self, excel_files: List[str]):
        self.data = []
        self.targets = []

        for file in excel_files:
            df = pd.read_excel(file, sheet_name='Sheet1')

            # 计算SOC（根据电压计算）
            max_voltage = df['Voltage(V)'].max()
            soc = df['Voltage(V)'] / max_voltage * 100

            # 选择特征
            features = df[['Voltage(V)', 'Temperature (C)_1', 'Current(A)']].values
            targets = soc.values

            self.data.append(features)
            self.targets.append(targets)

        self.data = np.concatenate(self.data, axis=0)
        self.targets = np.concatenate(self.targets, axis=0)

        # 数据标准化
        self.feature_scaler = StandardScaler()
        self.target_scaler = StandardScaler()

        self.data = self.feature_scaler.fit_transform(self.data)
        self.targets = self.target_scaler.fit_transform(self.targets.reshape(-1, 1)).flatten()

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        return torch.FloatTensor(self.data[idx]), torch.FloatTensor([self.targets[idx]])

    def get_scalers(self):
        return self.feature_scaler, self.target_scaler


class SOCModel(nn.Module):
    def __init__(self, input_size=3):
        super(SOCModel, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1)
        )

    def forward(self, x):
        return self.network(x)


def calculate_r2(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """
    计算真实的R²值

    参数:
    y_true: 真实值
    y_pred: 预测值

    返回:
    float: R²值
    """
    ss_res = np.sum((y_true - y_pred) ** 2)
    ss_tot = np.sum((y_true - np.mean(y_true)) ** 2)
    r2 = 1 - (ss_res / ss_tot)
    return r2


class Client:
    def __init__(self, client_id: int, data: Dataset, batch_size: int,
                 learning_rate: float, local_epochs: int):
        self.client_id = client_id
        self.data_loader = DataLoader(data, batch_size=batch_size, shuffle=True)
        self.learning_rate = learning_rate
        self.local_epochs = local_epochs
        self.model = SOCModel().to(device)
        self.losses = []
        self.r2_scores = []  # 新增R²分数列表

    def update(self, global_model_state: dict) -> Tuple[dict, float, float]:  # 修改返回类型
        self.model.load_state_dict(global_model_state)
        optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
        criterion = nn.MSELoss()

        epoch_losses = []
        all_predictions = []
        all_targets = []

        self.model.train()
        for _ in range(self.local_epochs):
            batch_losses = []
            for batch_data, batch_targets in self.data_loader:
                batch_data = batch_data.to(device)
                batch_targets = batch_targets.to(device)

                optimizer.zero_grad()
                outputs = self.model(batch_data)
                loss = criterion(outputs, batch_targets)
                loss.backward()
                optimizer.step()

                batch_losses.append(loss.item())

                # 收集预测值和真实值
                all_predictions.extend(outputs.detach().cpu().numpy())
                all_targets.extend(batch_targets.cpu().numpy())

            epoch_losses.append(np.mean(batch_losses))

        avg_loss = np.mean(epoch_losses)
        self.losses.append(avg_loss)

        # 计算R²分数
        r2_score = calculate_r2(np.array(all_targets), np.array(all_predictions))
        self.r2_scores.append(r2_score)

        return self.model.state_dict(), avg_loss, r2_score


class FederatedServer:
    def __init__(self, num_clients: int, global_epochs: int):
        self.num_clients = num_clients
        self.global_epochs = global_epochs
        self.global_model = SOCModel().to(device)
        self.clients: List[Client] = []
        self.global_losses = []
        self.global_r2_scores = []  # 新增全局R²分数列表

    def add_client(self, client: Client):
        self.clients.append(client)

    def aggregate_models(self, client_states: List[dict]) -> dict:
        aggregated_state = {}
        for key in client_states[0].keys():
            aggregated_state[key] = torch.stack([state[key] for state in client_states]).mean(dim=0)
        return aggregated_state

    def train(self) -> Tuple[List[float], List[float]]:  # 修改返回类型
        for epoch in range(self.global_epochs):
            print(f"Global Epoch {epoch + 1}/{self.global_epochs}")

            client_states = []
            epoch_losses = []
            epoch_r2_scores = []  # 新增R²分数列表

            for client in self.clients:
                client_state, client_loss, client_r2 = client.update(self.global_model.state_dict())
                client_states.append(client_state)
                epoch_losses.append(client_loss)
                epoch_r2_scores.append(client_r2)

            avg_loss = np.mean(epoch_losses)
            avg_r2 = np.mean(epoch_r2_scores)  # 计算平均R²分数
            self.global_losses.append(avg_loss)
            self.global_r2_scores.append(avg_r2)  # 保存全局R²分数

            aggregated_state = self.aggregate_models(client_states)
            self.global_model.load_state_dict(aggregated_state)

            print(f"Average Loss: {avg_loss:.4f}, Average R²: {avg_r2:.4f}")

        return self.global_losses, self.global_r2_scores


def evaluate_model(model, test_loader, criterion, target_scaler):
    model.eval()
    total_loss = 0
    predictions = []
    targets = []

    with torch.no_grad():
        for batch_data, batch_targets in test_loader:
            batch_data = batch_data.to(device)
            batch_targets = batch_targets.to(device)

            outputs = model(batch_data)
            loss = criterion(outputs, batch_targets)
            total_loss += loss.item()

            predictions.extend(outputs.cpu().numpy())
            targets.extend(batch_targets.cpu().numpy())

    # 反标准化得到实际的SOC值
    predictions = target_scaler.inverse_transform(np.array(predictions).reshape(-1, 1)).flatten()
    targets = target_scaler.inverse_transform(np.array(targets).reshape(-1, 1)).flatten()

    # 计算R²分数
    r2_score = calculate_r2(targets, predictions)

    return total_loss / len(test_loader), predictions, targets, r2_score


def plot_training_loss(losses_dict: Dict[int, List[float]], save_path: str):
    plt.figure(figsize=(4, 2.5))

    # Set font family to Times New Roman
    plt.rcParams['font.family'] = 'Times New Roman'
    plt.rcParams['font.size'] = 8

    # Set colors
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

    # Plot loss curves
    for (num_clients, losses), color in zip(losses_dict.items(), colors):
        plt.plot(losses, color=color, label=f'{num_clients} vehicles', linewidth=1)

    # Configure axes
    plt.xlabel('Number of global iteration # t', fontsize=8, fontname='Times New Roman')
    plt.ylabel('Loss', fontsize=8, fontname='Times New Roman')

    # Set axis limits and ticks
    plt.ylim(-0.2, 1.2)
    plt.xlim(-2, 52)
    plt.yticks(np.arange(0, 1.1, 0.2))
    plt.xticks(np.arange(0, 51, 10))

    # Move ticks inside
    plt.tick_params(axis='both', direction='in')

    # Add legend with frame
    plt.legend(fontsize=8)

    plt.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    plt.close()


def plot_all_prediction_performance(r2_scores_dict: Dict[int, List[float]], save_path: str):
    plt.figure(figsize=(4, 2.5))

    # Set font family to Times New Roman
    plt.rcParams['font.family'] = 'Times New Roman'
    plt.rcParams['font.size'] = 8

    # Set colors
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

    # Plot R² curves
    x = np.arange(50)  # 0到49的迭代次数
    for (num_clients, r2_scores), color in zip(r2_scores_dict.items(), colors):
        plt.plot(x, r2_scores, color=color, label=f'{num_clients} vehicles', linewidth=1)

    # Configure axes
    plt.xlabel('Number of global iteration # t', fontsize=8, fontname='Times New Roman')
    plt.ylabel('R²', fontsize=8, fontname='Times New Roman')

    # Set axis limits and ticks
    plt.ylim(-0.2, 1.2)
    plt.xlim(-2, 52)
    plt.yticks(np.arange(0, 1.1, 0.2))
    plt.xticks(np.arange(0, 51, 10))

    # Move ticks inside
    plt.tick_params(axis='both', direction='in')

    # Add legend
    plt.legend(fontsize=8)

    plt.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    plt.close()


def main():
    # 配置参数
    CLIENT_NUMBERS = [20, 40, 60, 80, 100]
    GLOBAL_EPOCHS = 50
    LOCAL_EPOCHS = 3
    LEARNING_RATE = 0.0001
    BATCH_SIZE = 32
    TEST_SPLIT = 0.2

    excel_files = [
        'D:/wp123/Code/python/FL-AELE/dataset/A1-007-DST-US06-FUDS-10-20120815.xlsx',
        'D:/wp123/Code/python/FL-AELE/dataset/A1-007-DST-US06-FUDS-20-20120817.xlsx',
        'D:/wp123/Code/python/FL-AELE/dataset/A1-007-DST-US06-FUDS-30-20120820.xlsx',
        'D:/wp123/Code/python/FL-AELE/dataset/A1-007-DST-US06-FUDS-40-20120822.xlsx',
        'D:/wp123/Code/python/FL-AELE/dataset/A1-007-DST-US06-FUDS-50-20120824.xlsx'
    ]

    # 创建完整数据集
    full_dataset = SOCDataset(excel_files)
    _, target_scaler = full_dataset.get_scalers()

    # 分割训练集和测试集
    test_size = int(len(full_dataset) * TEST_SPLIT)
    train_size = len(full_dataset) - test_size
    train_dataset, test_dataset = random_split(full_dataset, [train_size, test_size])

    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)
    criterion = nn.MSELoss()

    # 存储不同客户端数量的训练结果和预测结果
    all_losses = {}
    all_r2_scores = {}  # 新增R²分数字典
    all_predictions = {}

    # 对每个客户端数量进行训练
    for num_clients in CLIENT_NUMBERS:
        print(f"\nTraining with {num_clients} clients...")

        # 创建服务器
        server = FederatedServer(num_clients, GLOBAL_EPOCHS)

        # 为每个客户端分配数据
        data_per_client = train_size // num_clients

        # 创建并添加客户端
        for i in range(num_clients):
            start_idx = i * data_per_client
            end_idx = start_idx + data_per_client
            client_dataset = torch.utils.data.Subset(train_dataset, range(start_idx, end_idx))
            client = Client(i, client_dataset, BATCH_SIZE, LEARNING_RATE, LOCAL_EPOCHS)
            server.add_client(client)

        # 训练模型
        losses, r2_scores = server.train()
        all_losses[num_clients] = losses
        all_r2_scores[num_clients] = r2_scores  # 保存R²分数

        # 评估模型
        test_loss, predictions, targets, test_r2 = evaluate_model(
            server.global_model, test_loader, criterion, target_scaler)

        # 存储预测结果
        all_predictions[num_clients] = (predictions, targets)

        # 保存模型
        model_path = os.path.join(OUTPUT_DIR, f'model_{num_clients}_clients.pth')
        torch.save(server.global_model.state_dict(), model_path)

        print(f"Test Loss for {num_clients} clients: {test_loss:.4f}")
        print(f"Test R² for {num_clients} clients: {test_r2:.4f}")

    # 绘制训练损失曲线
    loss_plot_path = os.path.join(OUTPUT_DIR, 'training_losses.pdf')
    plot_training_loss(all_losses, loss_plot_path)

    # 绘制预测性能图 (R²)
    pred_plot_path = os.path.join(OUTPUT_DIR, 'all_prediction_performance.pdf')
    plot_all_prediction_performance(all_r2_scores, pred_plot_path)  # 使用R²分数

    # 保存训练损失数据
    loss_data_path = os.path.join(OUTPUT_DIR, 'training_losses.json')
    with open(loss_data_path, 'w') as f:
        json.dump({str(k): v for k, v in all_losses.items()}, f)

    # 保存R²分数数据
    r2_data_path = os.path.join(OUTPUT_DIR, 'r2_scores.json')
    with open(r2_data_path, 'w') as f:
        json.dump({str(k): v for k, v in all_r2_scores.items()}, f)

    # 打印所有配置的性能指标
    for num_clients, (predictions, targets) in all_predictions.items():
        mse = np.mean((predictions - targets) ** 2)
        mae = np.mean(np.abs(predictions - targets))
        r2 = calculate_r2(targets, predictions)  # 使用真实R²计算函数

        print(f"\nPerformance metrics for {num_clients} clients:")
        print(f"MSE: {mse:.4f}")
        print(f"MAE: {mae:.4f}")
        print(f"R²: {r2:.4f}")


if __name__ == "__main__":
    main()