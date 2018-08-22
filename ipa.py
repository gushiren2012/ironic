ironic-python-agent

ironic_python_agent/agent.py
class IronicPythonAgentStatus(encoding.Serializable)
	serializable_fields = ('started_at', 'version')
	
	def __init__(self, started_at, version):	//agent的状态
		self.started_at = started_at
        self.version = version
		

class IronicPythonAgentHeartbeater(threading.Thread):
	def __init__(self, agent):	//初始化heartbeat的线程
	def run(self):				//开始心跳
	def do_heartbeat(self):		//发送心跳到ironic
	def force_heartbeat(self):
	def stop(self):				//停止心跳线程
	
	
class IronicPythonAgent(base.ExecuteCommandMixin)：
	def get_status(self):		//获取agent的状态信息
	def _get_route_source(self, dest)://获取ip地址并向目标发送包
	def set_agent_advertise_addr(self)://为agent设置公布的IP地址
	def get_node_uuid(self)：//获取ironic node uuid
	def list_command_results(self)://
	def get_command_result(self, result_id):
	def force_heartbeat(self):
	def _wait_for_interface(self):
	def serve_ipa_api(self)://提供api
	def run(self)://运行ipa
	
	
ironic_python_agent/extensions/rescue.py
PASSWORD_FILE = '/etc/ipa-rescue-config/ipa-rescue-password
class RescueExtension(base.BaseAgentExtension):
	def make_salt(self)://对救援密码进行哈希
	def write_rescue_password(self, rescue_password="")://IPA退出后写入密码到文件
	def finalize_rescue(self, rescue_password="")://写入完密码关闭api

	
	
ironic_python_agent/extensions/standby.py
def _image_location(image_info)://在本地文件系统中获取镜像的位置
def _path_to_script(script)://获取ipa脚本的路径
def _write_partition_image(image, image_info, device)://调用diskutil来创建隔断并编写分区映像
def _write_whole_disk_image(image, image_info, device)://将整个磁盘映像写入指定的设备
def _write_image(image_info, device)://
class ImageDownload(object):
	def _download_file(self, image_info, url)://下载镜像文件
	def md5sum(self)://md5校验
		 
def _verify_image(image_info, image_location, checksum):
def _download_image(image_info)://将指定的镜像下载到本地文件系统
def _validate_image_info(ext, image_info=None, **kwargs)://验证imageinfo字典有所有必需的信息
	
	
	
ironic_python_agent/dmi_inspector.py
def collect_dmidecode_info(data, failures)://收集详细的处理器、内存和bios信息
def parse_dmi(data)://解析dmidecode输出，返回一个字典
	
	
ironic_python_agent/hardware.py
def _get_device_info(dev, devclass, field)://根据设备类和字段获取设备信息
def _get_system_lshw_dict()://lshw获取系统信息转换成json格式
def list_all_block_devices(block_type='disk')://列出所有物理块设备
def _check_for_iscsi()：
def _get_managers()://按优先顺序获取硬件管理器列表
def dispatch_to_all_managers(method, *args, **kwargs)://按照排序的优先顺序调度给定的方法
def dispatch_to_managers(method, *args, **kwargs):
def load_managers()://将硬件管理器预加载到缓存中
def cache_node(node)://将节点对象存储在硬件模块中以方便使用
def get_cached_node()://

class HardwareManager(object):
	def erase_devices(self, node, ports)://擦除保存用户数据的任何设备
	def wait_for_disks(self)://等待根磁盘出现
	def list_hardware_info(self)://将完整的硬件清单作为可串行字典返回
	def get_clean_steps(self, node, ports):
	def get_version(self)://获得这个硬件管理器的名称和版本

class GenericHardwareManager(HardwareManager):
	def evaluate_hardware_support(self)://初始化通用方法
	def collect_lldp_data(self, interface_names)://从节点收集并转换LLDP信息'
	def get_interface_info(self, interface_name)://收集网卡信息
	def get_ipv4_addr(self, interface_id)://收集ipv4地址
	def get_bios_given_nic_name(self, interface_name)://根据NICs名称收集BIOS
	def list_network_interfaces(self):
	def get_cpus(self):
	def get_memory(self):
	def list_block_devices(self):
	def get_os_install_device(self):
	def get_system_vendor_info(self):
	def get_boot_info(self):
	def erase_block_device(self, node, block_device):
	def erase_devices_metadata(self, node, ports)://尝试删除磁盘设备元数据
	def _shred_block_device(self, node, block_device)://使用Shred擦除块设备
	def _is_virtual_media_device(self, block_device):
	def _get_ata_security_lines(self, block_device):
	def _ata_erase(self, block_device)://调用hdparm进行安全擦除
	def get_bmc_address(self)://尝试检测BMC IP地址
	def get_clean_steps(self, node, ports):
	
ironic_python_agent/inspector.py
def inspect()://可以选择对当前节点运行检查
def call_inspector(data, failures)://将数据发布inspector
def _normalize_mac(mac)://转换mac地址的格式
def wait_for_dhcp()://等到NIC通过DHCP获取IP地址或发生超时	
def collect_default(data, failures)://这是默认调用的唯一收集器,收集hardwaremanager返回的硬件信息
def collect_logs(data, failures)://从ramdisk收集日志
def collect_extra_hardware(data, failures)://使用“硬件检测”实用程序收集详细清单
def collect_pci_devices_info(data, failures)://收集PCI设备列表

ironic_python_agent/ironic_api_client.py
class APIClient(object):
	def _request(self, method, path, data=None, headers=None, **kwargs):
	def _get_ironic_api_version_header(self, version=MIN_IRONIC_VERSION):
	def _get_ironic_api_version(self):
	def heartbeat(self, uuid, advertise_address):
	def lookup_node(self, hardware_info, timeout, starting_interval,
                    node_uuid=None):
	def _do_lookup(self, hardware_info, node_uuid):
	def _get_agent_url(self, advertise_address):
	
	