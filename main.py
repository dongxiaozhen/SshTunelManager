import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import paramiko
import threading
import time
import os
import socket
import select
import json
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)


class ConfigManager:
    def __init__(self, config_path=None):
        if config_path:
            self.config_file = config_path
            self.config_dir = os.path.dirname(config_path)
        else:
            self.config_dir = os.path.expanduser("./")
            self.config_file = os.path.join(self.config_dir, "tunnels.json")
        self.ensure_config_dir()

    def set_config_path(self, config_path):
        self.config_file = config_path
        self.config_dir = os.path.dirname(config_path)
        self.ensure_config_dir()

    def ensure_config_dir(self):
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

    def save_config(self, tunnels_config, tags_config):
        config = {
            "tunnels": tunnels_config,
            "tags": tags_config,
            "last_updated": datetime.now().isoformat()
        }
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"保存配置失败: {e}")
            return False

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    return config.get("tunnels", []), config.get("tags", {})
            return [], {}
        except Exception as e:
            print(f"加载配置失败: {e}")
            return [], {}


class CredentialsDialog:
    def __init__(self, parent, hostname):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"SSH Credentials for {hostname}")
        self.dialog.geometry("300x200")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)

        # 居中显示
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

        # 创建输入框和标签
        ttk.Label(self.dialog, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username = ttk.Entry(self.dialog)
        self.username.insert(0, "root")
        self.username.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.dialog, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password = ttk.Entry(self.dialog, show="*")
        self.password.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(self.dialog, text="Port:").grid(row=2, column=0, padx=5, pady=5)
        self.port = ttk.Entry(self.dialog)
        self.port.insert(0, "22")
        self.port.grid(row=2, column=1, padx=5, pady=5)

        # 创建按钮
        button_frame = ttk.Frame(self.dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="Connect", command=self.connect).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.LEFT, padx=5)

        self.result = None
        
        # 绑定回车键
        self.dialog.bind('<Return>', lambda e: self.connect())
        self.dialog.bind('<Escape>', lambda e: self.cancel())

    def connect(self):
        try:
            port = int(self.port.get())
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
            self.result = {
                "username": self.username.get(),
                "password": self.password.get(),
                "port": port,
            }
            self.dialog.destroy()
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def cancel(self):
        self.result = None
        self.dialog.destroy()

    def show(self):
        self.username.focus()
        self.dialog.wait_window()
        return self.result


class SSHTunnel:
    def __init__(self, hostname, local_port, remote_port, root, tunnel_id=None, name="", target_ip=None):
        self.hostname = hostname
        self.local_port = local_port
        self.remote_port = remote_port
        self.target_ip = target_ip if target_ip and target_ip.strip() else hostname
        self.root = root
        self.ssh = None
        self.tunnel = None
        self.is_running = False
        self.thread = None
        self.server_socket = None
        self.accept_thread = None
        self.forward_threads = []
        self.tunnel_id = tunnel_id or f"{hostname}:{local_port}->{self.target_ip}:{remote_port}"
        self.name = name or self.tunnel_id
        self.start_time = None

    def _accept_connections(self):
        logging.info(f"[{self.name}] 连接接受线程开始运行")
        while self.is_running:
            try:
                r, _, _ = select.select([self.server_socket], [], [], 1.0)
                if not r:
                    continue

                if not self.is_running:
                    break

                client_socket, addr = self.server_socket.accept()
                logging.debug(f"[{self.name}] 接受新连接: {addr}")

                if not self.ssh or not self.ssh.get_transport() or not self.ssh.get_transport().is_active():
                    logging.error(f"[{self.name}] SSH连接无效，拒绝客户端连接")
                    client_socket.close()
                    continue
                
                target_host = "127.0.0.1" if self.target_ip == self.hostname else self.target_ip

                # 使用target_ip而不是hostname来创建通道
                channel = self.ssh.get_transport().open_channel(
                    "direct-tcpip",
                    (target_host, self.remote_port),
                    (addr[0], client_socket.getsockname()[1]),
                )

                if not channel:
                    logging.error(f"[{self.name}] 无法创建SSH通道到 {self.target_ip}:{self.remote_port}")
                    client_socket.close()
                    continue

                logging.debug(f"[{self.name}] 为连接 {addr} 创建转发线程到 {self.target_ip}:{self.remote_port}")
                forward_thread = threading.Thread(
                    target=self._forward_data, 
                    args=(client_socket, channel),
                    name=f"Forward-{self.name}-{addr[0]}:{addr[1]}"
                )
                forward_thread.daemon = True
                forward_thread.start()
                self.forward_threads.append(forward_thread)

            except socket.error as e:
                if self.is_running:
                    logging.warning(f"[{self.name}] Socket错误: {e}")
                else:
                    break
            except Exception as e:
                if self.is_running:
                    logging.error(f"[{self.name}] 接受连接时出错: {e}")
                else:
                    break
        
        logging.info(f"[{self.name}] 连接接受线程结束")

    def _forward_data(self, client_socket, channel):
        connection_id = f"{client_socket.getpeername()}"
        logging.debug(f"[{self.name}] 开始为连接 {connection_id} 转发数据到 {self.target_ip}:{self.remote_port}")
        
        try:
            while self.is_running:
                if not self.is_running:
                    break

                try:
                    r, _, _ = select.select([client_socket, channel], [], [], 1.0)
                    if not r:
                        continue

                    if not self.is_running:
                        break

                    if client_socket in r:
                        try:
                            data = client_socket.recv(1024)
                            if not data:
                                logging.debug(f"[{self.name}] 客户端 {connection_id} 关闭连接")
                                break
                            channel.send(data)
                        except Exception as e:
                            logging.debug(f"[{self.name}] 从客户端读取数据失败 {connection_id}: {e}")
                            break

                    if channel in r:
                        try:
                            data = channel.recv(1024)
                            if not data:
                                logging.debug(f"[{self.name}] SSH通道 {connection_id} 关闭")
                                break
                            client_socket.send(data)
                        except Exception as e:
                            logging.debug(f"[{self.name}] 从SSH通道读取数据失败 {connection_id}: {e}")
                            break
                            
                except select.error as e:
                    if self.is_running:
                        logging.debug(f"[{self.name}] select错误 {connection_id}: {e}")
                    break
                except Exception as e:
                    if self.is_running:
                        logging.debug(f"[{self.name}] 转发数据时出错 {connection_id}: {e}")
                    break

        except Exception as e:
            if self.is_running:
                logging.error(f"[{self.name}] 转发线程异常 {connection_id}: {e}")

        finally:
            logging.debug(f"[{self.name}] 清理连接 {connection_id}")
            try:
                channel.close()
            except:
                pass
            try:
                client_socket.close()
            except:
                pass

    def _keep_tunnel_alive(self):
        logging.info(f"[{self.name}] 保活线程开始运行")
        while self.is_running:
            try:
                if (
                    self.ssh
                    and self.ssh.get_transport()
                    and self.ssh.get_transport().is_active()
                ):
                    self.ssh.get_transport().send_ignore()
                    logging.debug(f"[{self.name}] 发送保活信号")
                else:
                    if self.is_running:
                        logging.warning(f"[{self.name}] SSH连接不活跃，停止隧道")
                        self.is_running = False
                        break
                
                for _ in range(30):
                    if not self.is_running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                if self.is_running:
                    logging.error(f"[{self.name}] 保活线程出错: {e}")
                    self.is_running = False
                break
        
        logging.info(f"[{self.name}] 保活线程结束")

    def start(self):
        if self.target_ip != self.hostname:
            logging.info(f"[{self.name}] 开始启动SSH隧道: {self.hostname}:{self.local_port}->{self.target_ip}:{self.remote_port}")
        else:
            logging.info(f"[{self.name}] 开始启动SSH隧道: {self.hostname}:{self.local_port}->{self.remote_port}")
        
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # 读取 SSH 配置
            ssh_config = paramiko.SSHConfig()
            config_path = os.path.expanduser("~/.ssh/config")
            if os.path.exists(config_path):
                logging.info(f"[{self.name}] 读取SSH配置文件: {config_path}")
                with open(config_path) as f:
                    ssh_config.parse(f)

                host_config = ssh_config.lookup(self.hostname)
                if "user" in host_config:
                    connect_hostname = host_config.get("hostname", self.hostname)
                    connect_port = int(host_config.get("port", 22))
                    username = host_config.get("user")
                    logging.info(f"[{self.name}] 使用SSH配置连接: {username}@{connect_hostname}:{connect_port}")
                    
                    connect_kwargs = {
                        "hostname": connect_hostname,
                        "port": connect_port,
                    }

                    if username:
                        connect_kwargs["username"] = username

                    if "identityfile" in host_config:
                        connect_kwargs["key_filename"] = host_config["identityfile"][0]
                        logging.info(f"[{self.name}] 使用密钥文件: {host_config['identityfile'][0]}")

                    self.ssh.connect(**connect_kwargs)
                else:
                    logging.info(f"[{self.name}] SSH配置中未找到主机，显示凭据对话框")
                    dialog = CredentialsDialog(self.root, self.hostname)
                    credentials = dialog.show()
                    if not credentials:
                        logging.warning(f"[{self.name}] 用户取消连接")
                        raise Exception("Connection cancelled")

                    logging.info(f"[{self.name}] 使用用户凭据连接: {credentials['username']}@{self.hostname}:{credentials['port']}")
                    self.ssh.connect(
                        hostname=self.hostname,
                        username=credentials["username"],
                        password=credentials["password"],
                        port=credentials["port"],
                    )
            else:
                logging.info(f"[{self.name}] SSH配置文件不存在，显示凭据对话框")
                dialog = CredentialsDialog(self.root, self.hostname)
                credentials = dialog.show()
                if not credentials:
                    logging.warning(f"[{self.name}] 用户取消连接")
                    raise Exception("Connection cancelled")

                logging.info(f"[{self.name}] 使用用户凭据连接: {credentials['username']}@{self.hostname}:{credentials['port']}")
                self.ssh.connect(
                    hostname=self.hostname,
                    username=credentials["username"],
                    password=credentials["password"],
                    port=credentials["port"],
                )

            logging.info(f"[{self.name}] SSH连接成功，开始创建本地端口监听")
            
            # 创建本地端口监听
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.local_port))
            self.server_socket.listen(100)
            self.server_socket.settimeout(1.0)
            
            logging.info(f"[{self.name}] 本地端口监听成功: 0.0.0.0:{self.local_port}")

            # 启动线程
            self.is_running = True
            self.start_time = datetime.now()
            self.forward_threads = []
            
            logging.info(f"[{self.name}] 启动连接接受线程")
            self.accept_thread = threading.Thread(target=self._accept_connections, name=f"Accept-{self.name}")
            self.accept_thread.daemon = True
            self.accept_thread.start()

            logging.info(f"[{self.name}] 启动保活线程")
            self.thread = threading.Thread(target=self._keep_tunnel_alive, name=f"KeepAlive-{self.name}")
            self.thread.daemon = True
            self.thread.start()

            if self.target_ip != self.hostname:
                logging.info(f"[{self.name}] SSH隧道启动完成 (通过 {self.hostname} 连接到 {self.target_ip})")
            else:
                logging.info(f"[{self.name}] SSH隧道启动完成")
            return True
        except Exception as e:
            logging.error(f"[{self.name}] 启动隧道失败: {e}")
            self.stop()
            return False

    def stop(self):
        if not self.is_running:
            logging.info(f"[{self.name}] 隧道已经停止，无需操作")
            return
            
        logging.info(f"[{self.name}] 开始停止SSH隧道")
        
        self.is_running = False
        logging.info(f"[{self.name}] 设置停止标志")

        if self.server_socket:
            try:
                logging.info(f"[{self.name}] 强制关闭服务器Socket")
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
            except Exception as e:
                logging.debug(f"[{self.name}] 关闭服务器Socket时出错: {e}")
            self.server_socket = None

        if self.ssh:
            try:
                logging.info(f"[{self.name}] 强制关闭SSH连接")
                transport = self.ssh.get_transport()
                if transport:
                    transport.close()
                self.ssh.close()
            except Exception as e:
                logging.debug(f"[{self.name}] 关闭SSH连接时出错: {e}")
            self.ssh = None

        threads_to_wait = []
        
        if self.accept_thread and self.accept_thread.is_alive():
            threads_to_wait.append(("Accept", self.accept_thread))
            
        if self.thread and self.thread.is_alive():
            threads_to_wait.append(("KeepAlive", self.thread))

        for thread_name, t in threads_to_wait:
            try:
                logging.debug(f"[{self.name}] 等待线程 {thread_name} 结束")
                t.join(timeout=1.0)
                if t.is_alive():
                    logging.warning(f"[{self.name}] 线程 {thread_name} 未在规定时间内结束")
                else:
                    logging.debug(f"[{self.name}] 线程 {thread_name} 已结束")
            except Exception as e:
                logging.debug(f"[{self.name}] 等待线程 {thread_name} 时出错: {e}")

        active_forward_threads = [t for t in self.forward_threads if t.is_alive()]
        if active_forward_threads:
            logging.info(f"[{self.name}] 等待 {len(active_forward_threads)} 个转发线程结束")
            time.sleep(0.5)
            
            still_alive = [t for t in active_forward_threads if t.is_alive()]
            if still_alive:
                logging.warning(f"[{self.name}] 还有 {len(still_alive)} 个转发线程未结束（这是正常的）")

        self.thread = None
        self.accept_thread = None
        self.forward_threads = []
        self.start_time = None
        
        logging.info(f"[{self.name}] SSH隧道停止完成")

    def to_dict(self):
        return {
            "tunnel_id": self.tunnel_id,
            "hostname": self.hostname,
            "local_port": self.local_port,
            "remote_port": self.remote_port,
            "target_ip": self.target_ip,
            "name": self.name
        }

    def get_status(self):
        if not self.is_running:
            return "已停止"
        
        if not self.ssh or not self.ssh.get_transport():
            return "连接丢失"
        
        if not self.ssh.get_transport().is_active():
            return "连接断开"
        
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            hours, remainder = divmod(elapsed.total_seconds(), 3600)
            minutes, _ = divmod(remainder, 60)
            return f"运行中 ({int(hours)}h{int(minutes)}m)"
        
        return "运行中"


class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Tunnel Manager - Enhanced with Target IP")
        self.root.geometry("1200x700")
        self.root.minsize(900, 600)
        
        self.tunnels = []
        self.config_manager = ConfigManager()
        self.saved_configs = []
        self.tags = {}
        
        self.load_saved_configs()
        
        self.create_ui()
        self.update_table()
        self.update_saved_configs_tree()
        
        self.start_auto_refresh()

    def create_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="选择配置文件路径", command=self.select_config_file)
        file_menu.add_separator()
        file_menu.add_command(label="导入配置", command=self.import_config)
        file_menu.add_command(label="导出配置", command=self.export_config)
        
        debug_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="调试", menu=debug_menu)
        debug_menu.add_command(label="显示详细日志", command=self.enable_debug_log)
        debug_menu.add_command(label="隐藏详细日志", command=self.disable_debug_log)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.active_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.active_frame, text="活动隧道")
        self.create_active_tunnels_tab()

        self.saved_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.saved_frame, text="保存的配置")
        self.create_saved_configs_tab()

        self.tags_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tags_frame, text="标签管理")
        self.create_tags_management_tab()

        self.status_bar = ttk.Label(main_frame, text=f"配置文件: {self.config_manager.config_file}", 
                                   relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))

        control_frame = ttk.Frame(self.active_frame)
        control_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        ttk.Button(control_frame, text="刷新状态", command=self.manual_refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="检查端口", command=self.check_ports_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="停止选中的隧道", command=self.stop_selected_tunnel).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="强制停止选中", command=self.force_stop_selected_tunnel).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="停止所有隧道", command=self.stop_all_tunnels).pack(side=tk.LEFT, padx=5)
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)

    def create_active_tunnels_tab(self):
        input_frame = ttk.LabelFrame(self.active_frame, text="添加新隧道", padding="5")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

       # 第一行：名称、SSH主机、目标IP（带提示）
        ttk.Label(input_frame, text="名称:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.name_input = ttk.Entry(input_frame, width=20)
        self.name_input.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        ttk.Label(input_frame, text="SSH主机:").grid(row=0, column=2, padx=(20, 5), pady=5, sticky=tk.W)
        self.hostname_input = ttk.Entry(input_frame, width=20)
        self.hostname_input.grid(row=0, column=3, padx=5, pady=5, sticky=(tk.W, tk.E))

        ttk.Label(input_frame, text="目标IP:").grid(row=0, column=4, padx=(20, 5), pady=5, sticky=tk.W)
        self.target_ip_input = ttk.Entry(input_frame, width=40)
        self.target_ip_input.grid(row=0, column=5, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        tip_label = ttk.Label(input_frame, text="(可选，留空则使用SSH主机)", font=('', 8), foreground="gray")
        tip_label.grid(row=0, column=6, padx=5, pady=5, sticky=tk.W)

        # 第二行：本地端口、远程端口
        ttk.Label(input_frame, text="本地端口:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.local_port_input = ttk.Entry(input_frame, width=10)
        self.local_port_input.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(input_frame, text="远程端口:").grid(row=1, column=2, padx=(20, 5), pady=5, sticky=tk.W)
        self.remote_port_input = ttk.Entry(input_frame, width=10)
        self.remote_port_input.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)

        # 添加列权重配置
        input_frame.columnconfigure(1, weight=1)  # 名称输入框可伸缩
        input_frame.columnconfigure(3, weight=1)  # SSH主机输入框可伸缩
        input_frame.columnconfigure(5, weight=1)  # 目标IP输入框可伸缩
        
        # 按钮
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=3, column=0, columnspan=6, padx=5, pady=5)
        
        ttk.Button(button_frame, text="添加隧道", command=self.add_tunnel).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="保存配置", command=self.save_current_config).pack(side=tk.LEFT, padx=2)

        active_frame = ttk.LabelFrame(self.active_frame, text="当前活动隧道", padding="5")
        active_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        columns = ("name", "hostname", "target_ip", "local_port", "remote_port", "status")
        self.tree = ttk.Treeview(active_frame, columns=columns, show="headings")
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        headers = {
            "name": ("名称", 180),
            "hostname": ("SSH主机", 120),
            "target_ip": ("目标IP", 120),
            "local_port": ("本地端口", 80),
            "remote_port": ("远程端口", 80),
            "status": ("状态", 120)
        }
        
        for col, (header, width) in headers.items():
            self.tree.heading(col, text=header)
            self.tree.column(col, width=width)

        scrollbar1 = ttk.Scrollbar(active_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar1.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=scrollbar1.set)

        self.tree.bind('<Double-1>', self.on_tunnel_double_click)
        
        self.tree_menu = tk.Menu(self.tree, tearoff=0)
        self.tree_menu.add_command(label="停止隧道", command=self.stop_selected_tunnel)
        self.tree.bind('<Button-3>', self.show_tree_menu)

        input_frame.columnconfigure(4, weight=1)
        self.active_frame.columnconfigure(0, weight=1)
        self.active_frame.rowconfigure(1, weight=1)
        active_frame.columnconfigure(0, weight=1)
        active_frame.rowconfigure(0, weight=1)

    def create_saved_configs_tab(self):
        toolbar_frame = ttk.Frame(self.saved_frame)
        toolbar_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(toolbar_frame, text="刷新", command=self.update_saved_configs_tree).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar_frame, text="删除选中", command=self.delete_selected_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar_frame, text="编辑", command=self.edit_selected_config).pack(side=tk.LEFT, padx=5)
        
        filter_frame = ttk.LabelFrame(toolbar_frame, text="过滤", padding="3")
        filter_frame.pack(side=tk.LEFT, padx=(20, 5))
        
        ttk.Label(filter_frame, text="标签:").grid(row=0, column=0, padx=2)
        self.tag_filter = ttk.Combobox(filter_frame, width=12, state="readonly")
        self.tag_filter.grid(row=0, column=1, padx=2)
        self.tag_filter.bind('<<ComboboxSelected>>', self.on_filter_changed)
        
        ttk.Label(filter_frame, text="名称:").grid(row=0, column=2, padx=(10, 2))
        self.name_filter = ttk.Entry(filter_frame, width=15)
        self.name_filter.grid(row=0, column=3, padx=2)
        self.name_filter.bind('<KeyRelease>', self.on_filter_changed)
        
        ttk.Button(filter_frame, text="清空", command=self.clear_filters).grid(row=0, column=4, padx=5)
        
        self.update_tag_filter()

        saved_frame = ttk.LabelFrame(self.saved_frame, text="保存的配置", padding="5")
        saved_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        columns = ("name", "hostname", "target_ip", "local_port", "remote_port", "tags")
        self.saved_tree = ttk.Treeview(saved_frame, columns=columns, show="headings")
        self.saved_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        headers = {
            "name": ("名称", 180),
            "hostname": ("SSH主机", 120),
            "target_ip": ("目标IP", 120),
            "local_port": ("本地端口", 80),
            "remote_port": ("远程端口", 80),
            "tags": ("标签", 150)
        }
        
        for col, (header, width) in headers.items():
            self.saved_tree.heading(col, text=header)
            self.saved_tree.column(col, width=width)

        scrollbar2 = ttk.Scrollbar(saved_frame, orient=tk.VERTICAL, command=self.saved_tree.yview)
        scrollbar2.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.saved_tree.configure(yscrollcommand=scrollbar2.set)

        self.saved_tree.bind('<Double-1>', self.on_saved_config_double_click)

        self.saved_frame.columnconfigure(0, weight=1)
        self.saved_frame.rowconfigure(1, weight=1)
        saved_frame.columnconfigure(0, weight=1)
        saved_frame.rowconfigure(0, weight=1)

    def create_tags_management_tab(self):
        input_frame = ttk.LabelFrame(self.tags_frame, text="标签管理", padding="5")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(input_frame, text="标签名:").grid(row=0, column=0, padx=5, pady=5)
        self.tag_name_input = ttk.Entry(input_frame, width=20)
        self.tag_name_input.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(input_frame, text="添加标签", command=self.add_tag).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(input_frame, text="删除标签", command=self.delete_tag).grid(row=0, column=3, padx=5, pady=5)

        tags_list_frame = ttk.LabelFrame(self.tags_frame, text="现有标签", padding="5")
        tags_list_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.tags_listbox = tk.Listbox(tags_list_frame)
        self.tags_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        tags_scrollbar = ttk.Scrollbar(tags_list_frame, orient=tk.VERTICAL, command=self.tags_listbox.yview)
        tags_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.tags_listbox.configure(yscrollcommand=tags_scrollbar.set)
        
        self.update_tags_list()

        self.tags_frame.columnconfigure(0, weight=1)
        self.tags_frame.rowconfigure(1, weight=1)
        tags_list_frame.columnconfigure(0, weight=1)
        tags_list_frame.rowconfigure(0, weight=1)

    def select_config_file(self):
        file_path = filedialog.asksaveasfilename(
            title="选择配置文件保存位置",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="tunnels.json"
        )
        
        if file_path:
            old_config_file = self.config_manager.config_file
            self.config_manager.set_config_path(file_path)
            
            if self.config_manager.save_config(self.saved_configs, self.tags):
                self.status_bar.config(text=f"配置文件: {file_path}")
                messagebox.showinfo("成功", f"配置文件路径已更改为: {file_path}")
            else:
                self.config_manager.set_config_path(old_config_file)
                messagebox.showerror("错误", "无法保存到新的配置文件路径")

    def import_config(self):
        file_path = filedialog.askopenfilename(
            title="选择要导入的配置文件",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                temp_manager = ConfigManager(file_path)
                imported_configs, imported_tags = temp_manager.load_config()
                
                if imported_configs or imported_tags:
                    for config in imported_configs:
                        existing = next((c for c in self.saved_configs if c["tunnel_id"] == config["tunnel_id"]), None)
                        if not existing:
                            self.saved_configs.append(config)
                    
                    self.tags.update(imported_tags)
                    
                    self.save_configs()
                    self.update_saved_configs_tree()
                    self.update_tag_filter()
                    self.update_tags_list()
                    
                    messagebox.showinfo("成功", f"已导入 {len(imported_configs)} 个配置和 {len(imported_tags)} 个标签")
                else:
                    messagebox.showwarning("警告", "配置文件为空或格式不正确")
            except Exception as e:
                messagebox.showerror("错误", f"导入失败: {str(e)}")

    def export_config(self):
        file_path = filedialog.asksaveasfilename(
            title="导出配置文件",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"tunnels_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if file_path:
            try:
                temp_manager = ConfigManager(file_path)
                if temp_manager.save_config(self.saved_configs, self.tags):
                    messagebox.showinfo("成功", f"配置已导出到: {file_path}")
                else:
                    messagebox.showerror("错误", "导出失败")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")

    def load_saved_configs(self):
        self.saved_configs, self.tags = self.config_manager.load_config()

    def save_configs(self):
        return self.config_manager.save_config(self.saved_configs, self.tags)

    def add_tunnel(self):
        hostname = self.hostname_input.get().strip()
        name = self.name_input.get().strip()
        target_ip = self.target_ip_input.get().strip()
        
        logging.info(f"用户尝试添加隧道: SSH主机={hostname}, 目标IP={target_ip or hostname}, 名称={name}")
        
        try:
            local_port = int(self.local_port_input.get())
            remote_port = int(self.remote_port_input.get())
        except ValueError:
            logging.error("添加隧道失败: 端口格式错误")
            messagebox.showerror("错误", "端口必须是数字")
            return

        if not hostname or not local_port or not remote_port:
            logging.error("添加隧道失败: 必填字段为空")
            messagebox.showerror("错误", "请至少填写SSH主机和端口")
            return

        for tunnel in self.tunnels:
            if tunnel.local_port == local_port:
                logging.warning(f"添加隧道失败: 本地端口 {local_port} 已被隧道 '{tunnel.name}' 使用")
                messagebox.showerror("错误", f"本地端口 {local_port} 已被使用")
                return

        final_target_ip = target_ip if target_ip else None  # 传递 None 而不是空字符串
        tunnel_name = name or f"{hostname}:{local_port}->{final_target_ip}:{remote_port}"
        
        if target_ip:
            logging.info(f"开始创建隧道: {tunnel_name} (通过 {hostname} 连接到 {target_ip})")
        else:
            logging.info(f"开始创建隧道: {tunnel_name}")
        
        tunnel = SSHTunnel(hostname, local_port, remote_port, self.root, name=tunnel_name, target_ip=final_target_ip)
        if tunnel.start():
            self.tunnels.append(tunnel)
            self.update_table()
            self.clear_inputs()
            logging.info(f"隧道 '{tunnel_name}' 添加成功")
        else:
            logging.error(f"隧道 '{tunnel_name}' 启动失败")
            messagebox.showerror("错误", "无法启动隧道")

    def save_current_config(self):
        hostname = self.hostname_input.get().strip()
        name = self.name_input.get().strip()
        target_ip = self.target_ip_input.get().strip()
        
        try:
            local_port = int(self.local_port_input.get())
            remote_port = int(self.remote_port_input.get())
        except ValueError:
            messagebox.showerror("错误", "端口必须是数字")
            return

        if not hostname or not local_port or not remote_port:
            messagebox.showerror("错误", "请至少填写SSH主机和端口")
            return

        final_target_ip = target_ip or hostname

        tag_dialog = TagSelectionDialog(self.root, list(self.tags.keys()))
        selected_tags = tag_dialog.show()
        
        config = {
            "tunnel_id": f"{hostname}:{local_port}->{final_target_ip}:{remote_port}",
            "hostname": hostname,
            "local_port": local_port,
            "remote_port": remote_port,
            "target_ip": final_target_ip,
            "name": name or f"{hostname}:{local_port}->{final_target_ip}:{remote_port}",
            "tags": selected_tags or [],
            "created": datetime.now().isoformat()
        }
        
        existing = next((c for c in self.saved_configs if c["tunnel_id"] == config["tunnel_id"]), None)
        if existing:
            if messagebox.askyesno("确认", "配置已存在，是否覆盖？"):
                idx = self.saved_configs.index(existing)
                self.saved_configs[idx] = config
        else:
            self.saved_configs.append(config)
        
        if self.save_configs():
            self.update_saved_configs_tree()
            self.clear_inputs()
            messagebox.showinfo("成功", "配置已保存")
        else:
            messagebox.showerror("错误", "保存配置失败")

    def clear_inputs(self):
        self.hostname_input.delete(0, tk.END)
        self.local_port_input.delete(0, tk.END)
        self.remote_port_input.delete(0, tk.END)
        self.target_ip_input.delete(0, tk.END)
        self.name_input.delete(0, tk.END)

    def clear_filters(self):
        self.tag_filter.set("全部")
        self.name_filter.delete(0, tk.END)
        self.update_saved_configs_tree()

    def update_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for tunnel in self.tunnels:
            display_target_ip = tunnel.target_ip if tunnel.target_ip != tunnel.hostname else "-"
            
            self.tree.insert(
                "",
                tk.END,
                values=(
                    tunnel.name,
                    tunnel.hostname,
                    display_target_ip,
                    str(tunnel.local_port),
                    str(tunnel.remote_port),
                    tunnel.get_status()
                ),
                tags=(tunnel.tunnel_id,),
            )

    def update_saved_configs_tree(self):
        for item in self.saved_tree.get_children():
            self.saved_tree.delete(item)

        filter_tag = self.tag_filter.get()
        filter_name = self.name_filter.get().strip().lower()
        
        for config in self.saved_configs:
            if filter_tag and filter_tag != "全部" and filter_tag not in config.get("tags", []):
                continue
            
            if filter_name and filter_name not in config["name"].lower():
                continue
                
            tags_str = ", ".join(config.get("tags", []))
            
            target_ip = config.get("target_ip", config["hostname"])
            display_target_ip = target_ip if target_ip != config["hostname"] else "-"
            
            self.saved_tree.insert(
                "",
                tk.END,
                values=(
                    config["name"],
                    config["hostname"],
                    display_target_ip,
                    str(config["local_port"]),
                    str(config["remote_port"]),
                    tags_str
                ),
                tags=(config["tunnel_id"],),
            )

    def update_tag_filter(self):
        tags = ["全部"] + list(self.tags.keys())
        self.tag_filter['values'] = tags
        if not self.tag_filter.get():
            self.tag_filter.set("全部")

    def update_tags_list(self):
        self.tags_listbox.delete(0, tk.END)
        for tag_name in self.tags.keys():
            self.tags_listbox.insert(tk.END, tag_name)

    def add_tag(self):
        tag_name = self.tag_name_input.get().strip()
        
        if not tag_name:
            messagebox.showerror("错误", "请输入标签名称")
            return
        
        if tag_name in self.tags:
            messagebox.showerror("错误", "标签已存在")
            return
        
        self.tags[tag_name] = {"created": datetime.now().isoformat()}
        if self.save_configs():
            self.update_tags_list()
            self.update_tag_filter()
            self.tag_name_input.delete(0, tk.END)
            messagebox.showinfo("成功", f"标签 '{tag_name}' 已添加")
        else:
            messagebox.showerror("错误", "保存标签失败")

    def delete_tag(self):
        selection = self.tags_listbox.curselection()
        if not selection:
            messagebox.showerror("错误", "请选择要删除的标签")
            return
        
        tag_name = self.tags_listbox.get(selection[0])
        
        if messagebox.askyesno("确认", f"确定要删除标签 '{tag_name}' 吗？\n这将从所有配置中移除该标签。"):
            del self.tags[tag_name]
            
            for config in self.saved_configs:
                if tag_name in config.get("tags", []):
                    config["tags"].remove(tag_name)
            
            if self.save_configs():
                self.update_tags_list()
                self.update_tag_filter()
                self.update_saved_configs_tree()
                messagebox.showinfo("成功", f"标签 '{tag_name}' 已删除")
            else:
                messagebox.showerror("错误", "删除标签失败")

    def on_filter_changed(self, event=None):
        self.update_saved_configs_tree()

    def on_tunnel_double_click(self, event):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            tunnel_tag = item['tags'][0]
            tunnel = next((t for t in self.tunnels if str(t.tunnel_id) == tunnel_tag), None)
            if tunnel and tunnel.is_running:
                if messagebox.askyesno("确认", f"确定要停止隧道 '{tunnel.name}' 吗？"):
                    self.stop_tunnel(tunnel)

    def show_tree_menu(self, event):
        try:
            item = self.tree.selection()[0]
            self.tree_menu.post(event.x_root, event.y_root)
        except IndexError:
            pass

    def stop_selected_tunnel(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要停止的隧道")
            return
            
        item = self.tree.item(selection[0])
        tunnel_tag = item['tags'][0]
        tunnel = next((t for t in self.tunnels if str(t.tunnel_id) == tunnel_tag), None)
        if tunnel:
            if messagebox.askyesno("确认", f"确定要停止隧道 '{tunnel.name}' 吗？"):
                self.stop_tunnel(tunnel)

    def force_stop_selected_tunnel(self):
        selection = self.tree.selection()
        if not selection:
            logging.warning("用户尝试强制停止隧道但未选择任何隧道")
            messagebox.showwarning("警告", "请先选择要强制停止的隧道")
            return
            
        item = self.tree.item(selection[0])
        tunnel_tag = item['tags'][0]
        tunnel = next((t for t in self.tunnels if str(t.tunnel_id) == tunnel_tag), None)
        if tunnel:
            logging.info(f"用户请求强制停止隧道: '{tunnel.name}'")
            if messagebox.askyesno("确认", f"确定要强制停止隧道 '{tunnel.name}' 吗？\n这将立即终止所有相关连接。"):
                self.force_stop_tunnel(tunnel)
        else:
            logging.error("无法找到选中的隧道对象")
            messagebox.showerror("错误", "无法找到选中的隧道")

    def force_stop_tunnel(self, tunnel):
        logging.info(f"强制停止隧道: '{tunnel.name}' ({tunnel.hostname}:{tunnel.local_port}->{tunnel.target_ip}:{tunnel.remote_port})")
        
        if tunnel not in self.tunnels:
            logging.warning(f"隧道 '{tunnel.name}' 不在活动隧道列表中")
            return
        
        tunnel.is_running = False
        
        try:
            if tunnel.server_socket:
                try:
                    tunnel.server_socket.shutdown(socket.SHUT_RDWR)
                    tunnel.server_socket.close()
                except:
                    pass
                tunnel.server_socket = None
            
            if tunnel.ssh:
                try:
                    transport = tunnel.ssh.get_transport()
                    if transport:
                        transport.close()
                    tunnel.ssh.close()
                except:
                    pass
                tunnel.ssh = None
            
            self.tunnels.remove(tunnel)
            self.update_table()
            
            logging.info(f"隧道 '{tunnel.name}' 已被强制停止")
            messagebox.showinfo("完成", f"隧道 '{tunnel.name}' 已被强制停止")
            
        except Exception as e:
            logging.error(f"强制停止隧道 '{tunnel.name}' 时出错: {e}")
            if tunnel in self.tunnels:
                self.tunnels.remove(tunnel)
                self.update_table()

    def stop_tunnel(self, tunnel):
        logging.info(f"用户请求停止隧道: '{tunnel.name}' ({tunnel.hostname}:{tunnel.local_port}->{tunnel.target_ip}:{tunnel.remote_port})")
        
        if tunnel not in self.tunnels:
            logging.warning(f"隧道 '{tunnel.name}' 不在活动隧道列表中")
            return
            
        logging.info(f"开始停止隧道: '{tunnel.name}'")
        try:
            tunnel.stop()
            if tunnel in self.tunnels:
                self.tunnels.remove(tunnel)
            self.update_table()
            logging.info(f"隧道 '{tunnel.name}' 已成功停止并从列表中移除")
        except Exception as e:
            logging.error(f"停止隧道 '{tunnel.name}' 时出错: {e}")
            if tunnel in self.tunnels:
                self.tunnels.remove(tunnel)
                self.update_table()
    
    def stop_all_tunnels(self):
        if not self.tunnels:
            logging.info("用户尝试停止所有隧道，但当前没有运行的隧道")
            messagebox.showinfo("信息", "当前没有运行的隧道")
            return
            
        tunnel_count = len(self.tunnels)
        logging.info(f"用户请求停止所有隧道，共 {tunnel_count} 个")
        
        if messagebox.askyesno("确认", f"确定要停止所有 {tunnel_count} 个隧道吗？"):
            tunnels_to_stop = self.tunnels.copy()
            failed_count = 0
            
            for tunnel in tunnels_to_stop:
                try:
                    logging.info(f"停止隧道: '{tunnel.name}'")
                    tunnel.stop()
                except Exception as e:
                    logging.error(f"停止隧道 '{tunnel.name}' 失败: {e}")
                    failed_count += 1
            
            self.tunnels.clear()
            self.update_table()
            
            if failed_count > 0:
                logging.warning(f"停止所有隧道完成，有 {failed_count} 个隧道停止时出错")
                messagebox.showwarning("警告", f"所有隧道已停止，但有 {failed_count} 个隧道停止时出错")
            else:
                logging.info("所有隧道已成功停止")
                messagebox.showinfo("完成", "所有隧道已停止")

    def on_saved_config_double_click(self, event):
        selection = self.saved_tree.selection()
        if selection:
            item = self.saved_tree.item(selection[0])
            tunnel_id = item['tags'][0]
            config = next((c for c in self.saved_configs if c["tunnel_id"] == tunnel_id), None)
            if config:
                logging.info(f"用户双击启动保存的配置: '{config['name']}'")
                self.start_tunnel_from_config(config)
            else:
                logging.error("无法找到双击的配置对象")

    def start_tunnel_from_config(self, config):
        logging.info(f"用户请求从配置启动隧道: '{config['name']}'")
        
        for tunnel in self.tunnels:
            if tunnel.local_port == config["local_port"]:
                logging.warning(f"启动隧道失败: 本地端口 {config['local_port']} 已被隧道 '{tunnel.name}' 使用")
                messagebox.showerror("错误", f"本地端口 {config['local_port']} 已被使用")
                return
        
        target_ip = config.get("target_ip", config["hostname"])
        
        if target_ip != config["hostname"]:
            logging.info(f"开始创建隧道: {config['name']} ({config['hostname']}:{config['local_port']}->{target_ip}:{config['remote_port']})")
        else:
            logging.info(f"开始创建隧道: {config['name']} ({config['hostname']}:{config['local_port']}->{config['remote_port']})")
        
        tunnel = SSHTunnel(
            config["hostname"],
            config["local_port"],
            config["remote_port"],
            self.root,
            tunnel_id=config["tunnel_id"],
            name=config["name"],
            target_ip=target_ip
        )
        
        if tunnel.start():
            self.tunnels.append(tunnel)
            self.update_table()
            logging.info(f"隧道 '{config['name']}' 启动成功")
        else:
            logging.error(f"隧道 '{config['name']}' 启动失败")
            messagebox.showerror("错误", "无法启动隧道")

    def delete_selected_config(self):
        selection = self.saved_tree.selection()
        if not selection:
            messagebox.showerror("错误", "请选择要删除的配置")
            return
        
        item = self.saved_tree.item(selection[0])
        tunnel_id = item['tags'][0]
        config = next((c for c in self.saved_configs if c["tunnel_id"] == tunnel_id), None)
        
        if config:
            if messagebox.askyesno("确认", f"确定要删除配置 '{config['name']}' 吗？"):
                self.saved_configs.remove(config)
                if self.save_configs():
                    self.update_saved_configs_tree()
                    messagebox.showinfo("成功", "配置已删除")
                else:
                    messagebox.showerror("错误", "删除配置失败")

    def edit_selected_config(self):
        selection = self.saved_tree.selection()
        if not selection:
            messagebox.showerror("错误", "请选择要编辑的配置")
            return
        
        item = self.saved_tree.item(selection[0])
        tunnel_id = item['tags'][0]
        config = next((c for c in self.saved_configs if c["tunnel_id"] == tunnel_id), None)
        
        if config:
            dialog = ConfigEditDialog(self.root, config, list(self.tags.keys()))
            result = dialog.show()
            if result:
                idx = self.saved_configs.index(config)
                self.saved_configs[idx] = result
                if self.save_configs():
                    self.update_saved_configs_tree()
                    messagebox.showinfo("成功", "配置已更新")
                else:
                    messagebox.showerror("错误", "更新配置失败")

    def start_auto_refresh(self):
        self.auto_refresh_active = True
        self.schedule_refresh()
    
    def schedule_refresh(self):
        if hasattr(self, 'auto_refresh_active') and self.auto_refresh_active:
            self.check_tunnel_status()
            self.update_table()
            self.root.after(5000, self.schedule_refresh)
    
    def check_tunnel_status(self):
        if not hasattr(self, 'auto_refresh_active') or not self.auto_refresh_active:
            return
            
        tunnels_to_remove = []
        
        for tunnel in self.tunnels:
            if tunnel.is_running:
                if not tunnel.ssh or not tunnel.ssh.get_transport() or not tunnel.ssh.get_transport().is_active():
                    logging.warning(f"检测到隧道 '{tunnel.name}' 连接已断开，将其标记为停止")
                    tunnel.is_running = False
                    tunnels_to_remove.append(tunnel)
            else:
                if tunnel in self.tunnels:
                    tunnels_to_remove.append(tunnel)
        
        for tunnel in tunnels_to_remove:
            try:
                if tunnel in self.tunnels:
                    self.tunnels.remove(tunnel)
                    logging.info(f"自动清理失效隧道: '{tunnel.name}'")
            except Exception as e:
                logging.error(f"清理失效隧道 '{tunnel.name}' 时出错: {e}")
    
    def manual_refresh(self):
        logging.info("用户手动刷新隧道状态")
        was_active = getattr(self, 'auto_refresh_active', True)
        self.auto_refresh_active = False
        
        try:
            self.check_tunnel_status()
            self.update_table()
        finally:
            self.auto_refresh_active = was_active
            
        messagebox.showinfo("完成", "状态已刷新")
    
    def check_ports_status(self):
        logging.info("用户请求检查端口状态")
        
        if not self.tunnels:
            messagebox.showinfo("信息", "当前没有活动隧道")
            return
        
        port_status = []
        for tunnel in self.tunnels:
            is_listening = self._check_port_listening(tunnel.local_port)
            port_status.append(f"端口 {tunnel.local_port} ({tunnel.name}): {'监听中' if is_listening else '未监听'}")
            logging.info(f"端口状态检查 - {tunnel.local_port}: {'监听中' if is_listening else '未监听'}")
        
        status_text = "\n".join(port_status)
        messagebox.showinfo("端口状态", status_text)
    
    def _check_port_listening(self, port):
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(1)
            result = test_socket.connect_ex(('127.0.0.1', port))
            test_socket.close()
            return result == 0
        except Exception:
            return False
    
    def enable_debug_log(self):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info("已启用详细日志模式")
        messagebox.showinfo("调试", "已启用详细日志模式\n现在会显示所有连接和线程操作")
    
    def disable_debug_log(self):
        logging.getLogger().setLevel(logging.INFO)
        logging.info("已禁用详细日志模式")
        messagebox.showinfo("调试", "已禁用详细日志模式\n现在只显示重要操作信息")

    def on_closing(self):
        logging.info("用户关闭应用程序，开始清理资源")
        
        self.auto_refresh_active = False
        
        active_tunnels = len(self.tunnels)
        if active_tunnels > 0:
            logging.info(f"关闭应用前停止 {active_tunnels} 个活动隧道")
            for tunnel in self.tunnels:
                try:
                    logging.info(f"停止隧道: '{tunnel.name}'")
                    tunnel.stop()
                except Exception as e:
                    logging.error(f"停止隧道 '{tunnel.name}' 时出错: {e}")
        
        logging.info("应用程序清理完成，即将退出")
        self.root.destroy()


class TagSelectionDialog:
    def __init__(self, parent, available_tags):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("选择标签")
        self.dialog.geometry("300x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)

        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

        self.available_tags = available_tags
        self.selected_tags = []

        ttk.Label(self.dialog, text="选择标签 (用于分组):", font=('', 12, 'bold')).pack(pady=10)

        if available_tags:
            checkbox_frame = ttk.Frame(self.dialog)
            checkbox_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

            self.tag_vars = {}
            for tag in available_tags:
                var = tk.BooleanVar()
                self.tag_vars[tag] = var
                ttk.Checkbutton(checkbox_frame, text=tag, variable=var).pack(anchor=tk.W, pady=2)
        else:
            ttk.Label(self.dialog, text="暂无可用标签\n请先在标签管理页面创建标签", 
                     foreground="gray").pack(pady=50)
            self.tag_vars = {}

        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="确定", command=self.ok_clicked).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=self.cancel_clicked).pack(side=tk.LEFT, padx=5)

        self.result = None

    def ok_clicked(self):
        self.result = [tag for tag, var in self.tag_vars.items() if var.get()]
        self.dialog.destroy()

    def cancel_clicked(self):
        self.result = None
        self.dialog.destroy()

    def show(self):
        self.dialog.wait_window()
        return self.result


class ConfigEditDialog:
    def __init__(self, parent, config, available_tags):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("编辑配置")
        self.dialog.geometry("400x600")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)

        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

        self.config = config.copy()
        self.available_tags = available_tags

        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(expand=True, fill=tk.BOTH)

        info_frame = ttk.LabelFrame(main_frame, text="基本信息", padding="10")
        info_frame.pack(fill=tk.X, pady=5)

        ttk.Label(info_frame, text="名称:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.name_entry = ttk.Entry(info_frame, width=30)
        self.name_entry.insert(0, config.get("name", ""))
        self.name_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)

        ttk.Label(info_frame, text="SSH主机:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.hostname_entry = ttk.Entry(info_frame, width=30)
        self.hostname_entry.insert(0, config.get("hostname", ""))
        self.hostname_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)

        ttk.Label(info_frame, text="目标IP:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.target_ip_entry = ttk.Entry(info_frame, width=30)
        target_ip = config.get("target_ip", config.get("hostname", ""))
        if target_ip == config.get("hostname", ""):
            target_ip = ""
        self.target_ip_entry.insert(0, target_ip)
        self.target_ip_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=2)

        ttk.Label(info_frame, text="本地端口:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.local_port_entry = ttk.Entry(info_frame, width=30)
        self.local_port_entry.insert(0, str(config.get("local_port", "")))
        self.local_port_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2)

        ttk.Label(info_frame, text="远程端口:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.remote_port_entry = ttk.Entry(info_frame, width=30)
        self.remote_port_entry.insert(0, str(config.get("remote_port", "")))
        self.remote_port_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=2)

        info_frame.columnconfigure(1, weight=1)

        tags_frame = ttk.LabelFrame(main_frame, text="标签 (用于分组)", padding="10")
        tags_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        if available_tags:
            self.tag_vars = {}
            current_tags = config.get("tags", [])
            
            for tag in available_tags:
                var = tk.BooleanVar()
                if tag in current_tags:
                    var.set(True)
                self.tag_vars[tag] = var
                ttk.Checkbutton(tags_frame, text=tag, variable=var).pack(anchor=tk.W, pady=1)
        else:
            ttk.Label(tags_frame, text="暂无可用标签", foreground="gray").pack(pady=20)
            self.tag_vars = {}

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="保存", command=self.save_clicked).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=self.cancel_clicked).pack(side=tk.LEFT, padx=5)

        self.result = None

    def save_clicked(self):
        try:
            name = self.name_entry.get().strip()
            hostname = self.hostname_entry.get().strip()
            target_ip = self.target_ip_entry.get().strip()
            local_port = int(self.local_port_entry.get())
            remote_port = int(self.remote_port_entry.get())
            
            if not hostname:
                messagebox.showerror("错误", "SSH主机不能为空")
                return
            
            final_target_ip = target_ip or hostname
            selected_tags = [tag for tag, var in self.tag_vars.items() if var.get()]
            
            self.result = {
                "tunnel_id": f"{hostname}:{local_port}->{final_target_ip}:{remote_port}",
                "hostname": hostname,
                "target_ip": final_target_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "name": name or f"{hostname}:{local_port}->{final_target_ip}:{remote_port}",
                "tags": selected_tags,
                "created": self.config.get("created"),
                "modified": datetime.now().isoformat()
            }
            
            self.dialog.destroy()
            
        except ValueError:
            messagebox.showerror("错误", "端口必须是数字")

    def cancel_clicked(self):
        self.result = None
        self.dialog.destroy()

    def show(self):
        self.dialog.wait_window()
        return self.result


if __name__ == "__main__":
    print("=" * 70)
    print("SSH隧道管理器 - 增强版 (支持自定义目标IP)")
    print("=" * 70)
    print("💡 新功能：")
    print("   • 支持指定目标IP，实现 ssh -L 本地端口:目标IP:远程端口 SSH主机")
    print("   • 目标IP可选，留空则使用SSH主机作为目标")
    print("   • 在界面上会显示SSH主机和目标IP的区别")
    print("")
    print("💡 使用提示：")
    print("   • 浏览器访问一个页面会创建多个连接（正常现象）")
    print("   • 如果普通停止不生效，请使用'强制停止'")
    print("   • 可以通过'检查端口'按钮查看端口实际状态")
    print("   • 日志中的DEBUG信息已隐藏，只显示重要操作")
    print("=" * 70)
    
    logging.info("应用程序启动")
    
    root = tk.Tk()
    logging.info("创建主窗口")
    
    app = MainWindow(root)
    logging.info(f"加载配置完成，共有 {len(app.saved_configs)} 个保存的配置和 {len(app.tags)} 个标签")
    
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    logging.info("应用程序界面就绪，等待用户操作...")
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        logging.info("收到键盘中断信号，正在退出...")
        app.on_closing()
    except Exception as e:
        logging.error(f"应用程序运行时出错: {e}")
        raise