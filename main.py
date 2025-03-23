import tkinter as tk
from tkinter import ttk, messagebox
import paramiko
import threading
import time
import os
import socket
import select  # 添加 select 模块导入

class CredentialsDialog:
    def __init__(self, parent, hostname):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"SSH Credentials for {hostname}")
        self.dialog.geometry("300x200")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
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
        ttk.Button(self.dialog, text="Connect", command=self.connect).grid(row=3, column=0, columnspan=2, pady=20)
        
        self.result = None
        
    def connect(self):
        try:
            port = int(self.port.get())
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
            self.result = {
                'username': self.username.get(),
                'password': self.password.get(),
                'port': port
            }
            self.dialog.destroy()
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def show(self):
        self.dialog.wait_window()
        return self.result

class SSHTunnel:
    def __init__(self, hostname, local_port, remote_port, root):
        self.hostname = hostname
        self.local_port = local_port
        self.remote_port = remote_port
        self.root = root
        self.ssh = None
        self.tunnel = None
        self.is_running = False
        self.thread = None
        self.server_socket = None
        self.accept_thread = None

    def _accept_connections(self):
        while self.is_running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"New connection from {addr}")
                
                # 为每个连接创建新的通道
                channel = self.ssh.get_transport().open_channel(
                    "direct-tcpip",
                    ("127.0.0.1", self.remote_port),
                    ("127.0.0.1", self.local_port)
                )
                
                if not channel:
                    print("Failed to create channel")
                    client_socket.close()
                    continue
                
                # 启动数据转发线程
                thread = threading.Thread(
                    target=self._forward_data,
                    args=(client_socket, channel)
                )
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                if self.is_running:
                    print(f"Accept error: {e}")
                break

    def _forward_data(self, client_socket, channel):
        try:
            while self.is_running:
                r, w, x = select.select([client_socket, channel], [], [])
                if client_socket in r:
                    data = client_socket.recv(1024)
                    if len(data) == 0:
                        break
                    channel.send(data)
                if channel in r:
                    data = channel.recv(1024)
                    if len(data) == 0:
                        break
                    client_socket.send(data)
        except Exception as e:
            print(f"Forward error: {e}")
        finally:
            try:
                channel.close()
            except:
                pass
            try:
                client_socket.close()
            except:
                pass

    def _keep_tunnel_alive(self):
        while self.is_running:
            try:
                if self.ssh and self.ssh.get_transport() and self.ssh.get_transport().is_active():
                    self.ssh.get_transport().send_ignore()
                time.sleep(30)  # 每30秒发送一次保活信号
            except Exception as e:
                print(f"Tunnel keep-alive error: {e}")
                self.is_running = False
                break

    def start(self):
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 读取 SSH 配置
            ssh_config = paramiko.SSHConfig()
            config_path = os.path.expanduser('~/.ssh/config')
            if os.path.exists(config_path):
                with open(config_path) as f:
                    ssh_config.parse(f)
                
                # 尝试获取主机配置
                host_config = ssh_config.lookup(self.hostname)
                print(host_config)
                if 'user' in host_config:
                    # 使用配置中的主机名和端口
                    connect_hostname = host_config.get('hostname', self.hostname)
                    connect_port = int(host_config.get('port', 22))
                    username = host_config.get('user')
                    # 连接参数
                    connect_kwargs = {
                        'hostname': connect_hostname,
                        'port': connect_port,
                    }
                    
                    # 如果配置中有用户名，添加到连接参数
                    if username:
                        connect_kwargs['username'] = username
                    
                    # 如果配置中有密钥文件，添加到连接参数
                    if 'identityfile' in host_config:
                        connect_kwargs['key_filename'] = host_config['identityfile'][0]
                    
                    # 使用配置参数连接
                    self.ssh.connect(**connect_kwargs)
                else:
                    # 如果在配置中找不到主机，显示凭据对话框
                    dialog = CredentialsDialog(self.root, self.hostname)
                    credentials = dialog.show()
                    if not credentials:
                        raise Exception("Connection cancelled")
                    
                    # 使用对话框提供的凭据连接
                    self.ssh.connect(
                        hostname=self.hostname,
                        username=credentials['username'],
                        password=credentials['password'],
                        port=credentials['port']
                    )
            else:
                # 如果没有配置文件，显示凭据对话框
                dialog = CredentialsDialog(self.root, self.hostname)
                credentials = dialog.show()
                if not credentials:
                    raise Exception("Connection cancelled")
                
                # 使用对话框提供的凭据连接
                self.ssh.connect(
                    hostname=self.hostname,
                    username=credentials['username'],
                    password=credentials['password'],
                    port=credentials['port']
                )
            
            # 创建本地端口监听
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', self.local_port))
            self.server_socket.listen(100)  # 增加最大连接数
            
            # 启动连接接受线程
            self.is_running = True
            self.accept_thread = threading.Thread(target=self._accept_connections)
            self.accept_thread.daemon = True
            self.accept_thread.start()
            
            # 启动保活线程
            self.thread = threading.Thread(target=self._keep_tunnel_alive)
            self.thread.daemon = True
            self.thread.start()
            
            return True
        except Exception as e:
            print(f"Error starting tunnel: {e}")
            self.stop()  # 确保清理资源
            return False

    def stop(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.ssh:
            try:
                self.ssh.close()
            except:
                pass
        if self.thread:
            try:
                self.thread.join(timeout=1.0)  # 等待线程结束
            except:
                pass
        if self.accept_thread:
            try:
                self.accept_thread.join(timeout=1.0)  # 等待线程结束
            except:
                pass

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Tunnel Manager")
        self.root.geometry("800x800")  # 增加窗口高度以容纳历史记录
        self.tunnels = []
        self.history = []  # 添加历史记录列表
        
        # 创建主框架
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 创建输入框架
        input_frame = ttk.LabelFrame(main_frame, text="添加新隧道", padding="5")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # 主机名输入
        ttk.Label(input_frame, text="主机名:").grid(row=0, column=0, padx=5)
        self.hostname_input = ttk.Entry(input_frame, width=20)
        self.hostname_input.grid(row=0, column=1, padx=5)
        
        # 本地端口输入
        ttk.Label(input_frame, text="本地端口:").grid(row=0, column=2, padx=5)
        self.local_port_input = ttk.Entry(input_frame, width=10)
        self.local_port_input.grid(row=0, column=3, padx=5)
        
        # 远程端口输入
        ttk.Label(input_frame, text="远程端口:").grid(row=0, column=4, padx=5)
        self.remote_port_input = ttk.Entry(input_frame, width=10)
        self.remote_port_input.grid(row=0, column=5, padx=5)
        
        # 添加按钮
        add_button = ttk.Button(input_frame, text="添加隧道", command=self.add_tunnel)
        add_button.grid(row=0, column=6, padx=5)
        
        # 创建当前隧道表格
        current_frame = ttk.LabelFrame(main_frame, text="当前隧道", padding="5")
        current_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.tree = ttk.Treeview(current_frame, columns=("hostname", "local_port", "remote_port", "status", "action"), show="headings")
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 设置列标题
        self.tree.heading("hostname", text="主机名")
        self.tree.heading("local_port", text="本地端口")
        self.tree.heading("remote_port", text="远程端口")
        self.tree.heading("status", text="状态")
        self.tree.heading("action", text="操作")
        
        # 设置列宽
        self.tree.column("hostname", width=200)
        self.tree.column("local_port", width=100)
        self.tree.column("remote_port", width=100)
        self.tree.column("status", width=100)
        self.tree.column("action", width=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(current_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 创建历史记录表格
        history_frame = ttk.LabelFrame(main_frame, text="历史记录", padding="5")
        history_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.history_tree = ttk.Treeview(history_frame, columns=("hostname", "local_port", "remote_port", "action"), show="headings")
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 设置历史记录列标题
        self.history_tree.heading("hostname", text="主机名")
        self.history_tree.heading("local_port", text="本地端口")
        self.history_tree.heading("remote_port", text="远程端口")
        self.history_tree.heading("action", text="操作")
        
        # 设置历史记录列宽
        self.history_tree.column("hostname", width=200)
        self.history_tree.column("local_port", width=100)
        self.history_tree.column("remote_port", width=100)
        self.history_tree.column("action", width=100)
        
        # 添加历史记录滚动条
        history_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        history_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.history_tree.configure(yscrollcommand=history_scrollbar.set)
        
        # 配置网格权重
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        current_frame.columnconfigure(0, weight=1)
        current_frame.rowconfigure(0, weight=1)
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)

    def add_tunnel(self):
        hostname = self.hostname_input.get()
        try:
            local_port = int(self.local_port_input.get())
            remote_port = int(self.remote_port_input.get())
        except ValueError:
            messagebox.showerror("错误", "端口必须是数字")
            return

        if not hostname or not local_port or not remote_port:
            messagebox.showerror("错误", "请填写所有字段")
            return

        tunnel = SSHTunnel(hostname, local_port, remote_port, self.root)
        if tunnel.start():
            self.tunnels.append(tunnel)
            # 添加到历史记录
            self.history.append({
                'hostname': hostname,
                'local_port': local_port,
                'remote_port': remote_port
            })
            self.update_table()
            self.update_history()
            self.clear_inputs()
        else:
            messagebox.showerror("错误", "无法启动隧道")

    def clear_inputs(self):
        self.hostname_input.delete(0, tk.END)
        self.local_port_input.delete(0, tk.END)
        self.remote_port_input.delete(0, tk.END)

    def update_table(self):
        # 清除现有项目
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 添加新项目
        for tunnel in self.tunnels:
            item = self.tree.insert("", tk.END, values=(
                tunnel.hostname,
                str(tunnel.local_port),
                str(tunnel.remote_port),
                "运行中" if tunnel.is_running else "已停止",
                "停止"  # 为操作列添加默认文本
            ), tags=(str(id(tunnel)),))
            
            # 绑定点击事件到整行
            self.tree.tag_bind(str(id(tunnel)), '<Button-1>', 
                             lambda e, t=tunnel: self.stop_tunnel(t))

    def update_history(self):
        # 清除现有历史记录
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # 添加历史记录
        for record in self.history:
            item = self.history_tree.insert("", tk.END, values=(
                record['hostname'],
                str(record['local_port']),
                str(record['remote_port']),
                "重新连接"  # 为操作列添加默认文本
            ), tags=(str(id(record)),))
            
            # 绑定点击事件到整行
            self.history_tree.tag_bind(str(id(record)), '<Button-1>', 
                                     lambda e, r=record: self.reconnect_from_history(r))

    def reconnect_from_history(self, record):
        tunnel = SSHTunnel(record['hostname'], record['local_port'], record['remote_port'], self.root)
        if tunnel.start():
            self.tunnels.append(tunnel)
            self.update_table()
        else:
            messagebox.showerror("错误", "无法重新连接隧道")

    def stop_tunnel(self, tunnel):
        tunnel.stop()
        self.tunnels.remove(tunnel)
        self.update_table()

    def on_closing(self):
        for tunnel in self.tunnels:
            tunnel.stop()
        self.root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = MainWindow(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop() 