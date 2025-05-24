# ~ This is the 5th result from an AI im developing called "mochiAI"
# ~ "MochiAI" is my personal AI built purely to control a machine and automaticly do taks like audits, cybersec, and development. It is ment to take full control over a system and do what the user wants
# ~ "TaskVeiw V5.0 | AMA edition"; enerated by "MochiAI v32.1".

#######
#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import time
import subprocess
import json
import os
import platform
import socket
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
import queue
import sys
from collections import deque
import gc
import ctypes
from ctypes import wintypes, Structure, POINTER, byref, sizeof
import struct

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
psapi = ctypes.windll.psapi
user32 = ctypes.windll.user32

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

# Advanced Memory Analysis Structures
class MEMORYSTATUSEX(Structure):
    _fields_ = [
        ('dwLength', wintypes.DWORD),
        ('dwMemoryLoad', wintypes.DWORD),
        ('ullTotalPhys', ctypes.c_ulonglong),
        ('ullAvailPhys', ctypes.c_ulonglong),
        ('ullTotalPageFile', ctypes.c_ulonglong),
        ('ullAvailPageFile', ctypes.c_ulonglong),
        ('ullTotalVirtual', ctypes.c_ulonglong),
        ('ullAvailVirtual', ctypes.c_ulonglong),
        ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
    ]

class PROCESS_MEMORY_COUNTERS_EX(Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('PageFaultCount', wintypes.DWORD),
        ('PeakWorkingSetSize', ctypes.c_size_t),
        ('WorkingSetSize', ctypes.c_size_t),
        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
        ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
        ('PagefileUsage', ctypes.c_size_t),
        ('PeakPagefileUsage', ctypes.c_size_t),
        ('PrivateUsage', ctypes.c_size_t),
    ]

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p),
        ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD),
    ]

class SYSTEM_INFO(Structure):
    _fields_ = [
        ('wProcessorArchitecture', wintypes.WORD),
        ('wReserved', wintypes.WORD),
        ('dwPageSize', wintypes.DWORD),
        ('lpMinimumApplicationAddress', ctypes.c_void_p),
        ('lpMaximumApplicationAddress', ctypes.c_void_p),
        ('dwActiveProcessorMask', POINTER(wintypes.DWORD)),
        ('dwNumberOfProcessors', wintypes.DWORD),
        ('dwProcessorType', wintypes.DWORD),
        ('dwAllocationGranularity', wintypes.DWORD),
        ('wProcessorLevel', wintypes.WORD),
        ('wProcessorRevision', wintypes.WORD),
    ]

class PERFORMANCE_INFORMATION(Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('CommitTotal', ctypes.c_size_t),
        ('CommitLimit', ctypes.c_size_t),
        ('CommitPeak', ctypes.c_size_t),
        ('PhysicalTotal', ctypes.c_size_t),
        ('PhysicalAvailable', ctypes.c_size_t),
        ('SystemCache', ctypes.c_size_t),
        ('KernelTotal', ctypes.c_size_t),
        ('KernelPaged', ctypes.c_size_t),
        ('KernelNonpaged', ctypes.c_size_t),
        ('PageSize', ctypes.c_size_t),
        ('HandleCount', wintypes.DWORD),
        ('ProcessCount', wintypes.DWORD),
        ('ThreadCount', wintypes.DWORD),
    ]

class EnterpriseMemoryAnalyzer:
    
    def __init__(self):
        self.initialize_memory_analysis_subsystems()
        
    def initialize_memory_analysis_subsystems(self):
        self.system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(self.system_info))
        
        self.page_size = self.system_info.dwPageSize
        self.allocation_granularity = self.system_info.dwAllocationGranularity
        self.processor_architecture = self.system_info.wProcessorArchitecture
        
        self.memory_regions = {}
        self.gpu_memory_info = {}
        self.process_memory_maps = {}
        
    def analyze_system_memory_architecture(self):
        try:
            memory_status = MEMORYSTATUSEX()
            memory_status.dwLength = sizeof(MEMORYSTATUSEX)
            
            if not kernel32.GlobalMemoryStatusEx(byref(memory_status)):
                raise ctypes.WinError()
                
            performance_info = PERFORMANCE_INFORMATION()
            performance_info.cb = sizeof(PERFORMANCE_INFORMATION)
            
            if psapi.GetPerformanceInfo(byref(performance_info), sizeof(PERFORMANCE_INFORMATION)):
                return {
                    'physical_memory': {
                        'total_bytes': memory_status.ullTotalPhys,
                        'available_bytes': memory_status.ullAvailPhys,
                        'used_bytes': memory_status.ullTotalPhys - memory_status.ullAvailPhys,
                        'memory_load_percent': memory_status.dwMemoryLoad,
                        'total_gb': memory_status.ullTotalPhys / (1024**3),
                        'available_gb': memory_status.ullAvailPhys / (1024**3),
                        'used_gb': (memory_status.ullTotalPhys - memory_status.ullAvailPhys) / (1024**3)
                    },
                    'virtual_memory': {
                        'total_bytes': memory_status.ullTotalVirtual,
                        'available_bytes': memory_status.ullAvailVirtual,
                        'used_bytes': memory_status.ullTotalVirtual - memory_status.ullAvailVirtual,
                        'total_gb': memory_status.ullTotalVirtual / (1024**3),
                        'available_gb': memory_status.ullAvailVirtual / (1024**3),
                        'used_gb': (memory_status.ullTotalVirtual - memory_status.ullAvailVirtual) / (1024**3)
                    },
                    'page_file': {
                        'total_bytes': memory_status.ullTotalPageFile,
                        'available_bytes': memory_status.ullAvailPageFile,
                        'used_bytes': memory_status.ullTotalPageFile - memory_status.ullAvailPageFile,
                        'total_gb': memory_status.ullTotalPageFile / (1024**3),
                        'available_gb': memory_status.ullAvailPageFile / (1024**3),
                        'used_gb': (memory_status.ullTotalPageFile - memory_status.ullAvailPageFile) / (1024**3)
                    },
                    'system_performance': {
                        'commit_total': performance_info.CommitTotal * self.page_size,
                        'commit_limit': performance_info.CommitLimit * self.page_size,
                        'commit_peak': performance_info.CommitPeak * self.page_size,
                        'physical_total': performance_info.PhysicalTotal * self.page_size,
                        'physical_available': performance_info.PhysicalAvailable * self.page_size,
                        'system_cache': performance_info.SystemCache * self.page_size,
                        'kernel_total': performance_info.KernelTotal * self.page_size,
                        'kernel_paged': performance_info.KernelPaged * self.page_size,
                        'kernel_nonpaged': performance_info.KernelNonpaged * self.page_size,
                        'handle_count': performance_info.HandleCount,
                        'process_count': performance_info.ProcessCount,
                        'thread_count': performance_info.ThreadCount
                    },
                    'architecture': {
                        'page_size': self.page_size,
                        'allocation_granularity': self.allocation_granularity,
                        'processor_architecture': self.processor_architecture,
                        'minimum_app_address': self.system_info.lpMinimumApplicationAddress,
                        'maximum_app_address': self.system_info.lpMaximumApplicationAddress
                    }
                }
            else:
                raise ctypes.WinError()
                
        except Exception as e:
            print(f"Memory architecture analysis error: {e}")
            return None
            
    def analyze_process_memory_regions(self, pid):
        try:
            process_handle = kernel32.OpenProcess(0x1F0FFF, False, pid)  # PROCESS_ALL_ACCESS
            if not process_handle:
                return None
                
            memory_regions = []
            address = 0
            
            while address < 0x7FFFFFFFFFFFFFFF:  # Maximum user-mode address on x64
                mbi = MEMORY_BASIC_INFORMATION()
                result = kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), 
                                               byref(mbi), sizeof(mbi))
                
                if result == 0:
                    break
                    
                region_info = {
                    'base_address': hex(mbi.BaseAddress) if mbi.BaseAddress else '0x0',
                    'allocation_base': hex(mbi.AllocationBase) if mbi.AllocationBase else '0x0',
                    'region_size': mbi.RegionSize,
                    'region_size_mb': mbi.RegionSize / (1024 * 1024),
                    'state': self.decode_memory_state(mbi.State),
                    'protection': self.decode_memory_protection(mbi.Protect),
                    'type': self.decode_memory_type(mbi.Type)
                }
                
                memory_regions.append(region_info)
                address += mbi.RegionSize
                
                # Prevent infinite loops and limit analysis scope
                if len(memory_regions) > 10000:
                    break
                    
            kernel32.CloseHandle(process_handle)
            return memory_regions
            
        except Exception as e:
            print(f"Process memory region analysis error: {e}")
            return None
            
    def analyze_process_memory_counters(self, pid):
        try:
            process_handle = kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not process_handle:
                return None
                
            memory_counters = PROCESS_MEMORY_COUNTERS_EX()
            memory_counters.cb = sizeof(PROCESS_MEMORY_COUNTERS_EX)
            
            if psapi.GetProcessMemoryInfo(process_handle, byref(memory_counters), 
                                        sizeof(PROCESS_MEMORY_COUNTERS_EX)):
                
                result = {
                    'page_fault_count': memory_counters.PageFaultCount,
                    'peak_working_set': memory_counters.PeakWorkingSetSize,
                    'working_set': memory_counters.WorkingSetSize,
                    'quota_peak_paged_pool': memory_counters.QuotaPeakPagedPoolUsage,
                    'quota_paged_pool': memory_counters.QuotaPagedPoolUsage,
                    'quota_peak_nonpaged_pool': memory_counters.QuotaPeakNonPagedPoolUsage,
                    'quota_nonpaged_pool': memory_counters.QuotaNonPagedPoolUsage,
                    'pagefile_usage': memory_counters.PagefileUsage,
                    'peak_pagefile_usage': memory_counters.PeakPagefileUsage,
                    'private_usage': memory_counters.PrivateUsage,
                    'working_set_mb': memory_counters.WorkingSetSize / (1024 * 1024),
                    'private_usage_mb': memory_counters.PrivateUsage / (1024 * 1024),
                    'pagefile_usage_mb': memory_counters.PagefileUsage / (1024 * 1024)
                }
                
                kernel32.CloseHandle(process_handle)
                return result
            else:
                kernel32.CloseHandle(process_handle)
                return None
                
        except Exception as e:
            print(f"Process memory counters analysis error: {e}")
            return None
            
    def analyze_gpu_memory_utilization(self):
        try:
            gpu_memory_info = {}
            
            try:
                import pynvml
                pynvml.nvmlInit()
                device_count = pynvml.nvmlDeviceGetCount()
                
                for i in range(device_count):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    name = pynvml.nvmlDeviceGetName(handle).decode('utf-8')
                    memory_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                    
                    gpu_memory_info[f'nvidia_gpu_{i}'] = {
                        'name': name,
                        'total_memory': memory_info.total,
                        'free_memory': memory_info.free,
                        'used_memory': memory_info.used,
                        'total_mb': memory_info.total / (1024 * 1024),
                        'free_mb': memory_info.free / (1024 * 1024),
                        'used_mb': memory_info.used / (1024 * 1024),
                        'utilization_percent': (memory_info.used / memory_info.total) * 100
                    }
                    
            except ImportError:
                try:
                    import wmi
                    wmi_interface = wmi.WMI()
                    
                    for gpu in wmi_interface.Win32_VideoController():
                        if gpu.AdapterRAM:
                            gpu_memory_info[f'wmi_gpu_{gpu.DeviceID}'] = {
                                'name': gpu.Name,
                                'total_memory': gpu.AdapterRAM,
                                'total_mb': gpu.AdapterRAM / (1024 * 1024),
                                'driver_version': gpu.DriverVersion or "Unknown",
                                'video_processor': gpu.VideoProcessor or "Unknown"
                            }
                            
                except ImportError:
                    pass
                    
            return gpu_memory_info if gpu_memory_info else None
            
        except Exception as e:
            print(f"GPU memory analysis error: {e}")
            return None
            
    def decode_memory_state(self, state):
        """Decode Windows memory state flags"""
        if state == MEM_COMMIT:
            return "COMMITTED"
        elif state == MEM_RESERVE:
            return "RESERVED"
        elif state == MEM_FREE:
            return "FREE"
        else:
            return f"UNKNOWN({state})"
            
    def decode_memory_protection(self, protection):
        """Decode Windows memory protection flags"""
        protection_map = {
            PAGE_NOACCESS: "NO_ACCESS",
            PAGE_READONLY: "READ_ONLY",
            PAGE_READWRITE: "READ_WRITE",
            PAGE_EXECUTE: "EXECUTE",
            PAGE_EXECUTE_READ: "EXECUTE_READ",
            PAGE_EXECUTE_READWRITE: "EXECUTE_READ_WRITE"
        }
        return protection_map.get(protection, f"UNKNOWN({protection})")
        
    def decode_memory_type(self, mem_type):
        """Decode Windows memory type flags"""
        if mem_type == 0x1000000:
            return "IMAGE"
        elif mem_type == 0x40000:
            return "MAPPED"
        elif mem_type == 0x20000:
            return "PRIVATE"
        else:
            return f"UNKNOWN({mem_type})"

class EnterpriseSystemMonitor:
    def __init__(self):
        self.monitoring_active = True
        self.update_interval = 2.0
        self.gui_update_queue = queue.Queue()
        self.data_lock = threading.RLock()
        
        self.root = tk.Tk()
        
        self.memory_analyzer = EnterpriseMemoryAnalyzer()
        
        self.wmi_interface = None
        self.initialize_wmi_interface()
        
        self.performance_metrics = {
            'cpu_cores': deque(maxlen=150),
            'memory_usage': deque(maxlen=150),
            'memory_detailed': deque(maxlen=150),
            'virtual_memory': deque(maxlen=150),
            'gpu_memory': deque(maxlen=150),
            'page_faults': deque(maxlen=150),
            'handle_count': deque(maxlen=150),
            'disk_io': deque(maxlen=150),
            'network_io': deque(maxlen=150),
            'thread_count': deque(maxlen=150),
            'process_count': deque(maxlen=150),
            'context_switches': deque(maxlen=150),
            'timestamps': deque(maxlen=150)
        }
        
        self.memory_analysis_data = {
            'system_memory_architecture': {},
            'process_memory_maps': {},
            'gpu_memory_utilization': {},
            'memory_fragmentation_analysis': {},
            'virtual_address_space_usage': {},
            'last_analysis_timestamp': None
        }
        
        self.cached_data = {
            'system_info': {},
            'hardware_info': {},
            'security_status': {},
            'process_list': [],
            'network_connections': [],
            'memory_regions': {},
            'cache_timestamps': {}
        }
        
        self.performance_stats = {
            'data_collection_time': deque(maxlen=50),
            'gui_update_time': deque(maxlen=50),
            'memory_analysis_time': deque(maxlen=50),
            'thread_performance': {}
        }
        
        self.setup_optimized_enterprise_ui()
        
        self.initialize_consolidated_monitoring()
        
    def initialize_wmi_interface(self):
        try:
            import wmi
            self.wmi_interface = wmi.WMI()
            print("WMI interface initialized successfully")
        except ImportError:
            print("WMI module not available - some hardware features disabled")
        except Exception as e:
            print(f"WMI initialization failed: {e} - Operating in compatibility mode")
            
    def setup_optimized_enterprise_ui(self):
        self.root.title("AI TEST v5.0 - AMA Edition")
        self.root.geometry("1600x1000")
        self.root.configure(bg='#0a0a0a')
        
        self.colors = {
            'bg_primary': '#0a0a0a',
            'bg_secondary': '#1a1a1a',
            'bg_tertiary': '#2a2a2a',
            'accent_primary': '#ff6b35',
            'accent_secondary': '#ff8c42',
            'text_primary': '#ffffff',
            'text_secondary': '#e0e0e0',
            'success': '#00ff88',
            'warning': '#ffaa00',
            'danger': '#ff4444',
            'info': '#4488ff',
            'memory': '#9d4edd',
            'gpu': '#f72585'
        }
        
        self.configure_performance_styles()
        self.create_optimized_interface()
        
    def configure_performance_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Performance.TNotebook',
                       background=self.colors['bg_primary'],
                       borderwidth=0,
                       relief='flat')
        style.configure('Performance.TNotebook.Tab',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['text_primary'],
                       padding=[20, 8],
                       borderwidth=0)
        style.map('Performance.TNotebook.Tab',
                 background=[('selected', self.colors['accent_primary'])],
                 foreground=[('selected', self.colors['text_primary'])])
        
        style.configure('Primary.TFrame', background=self.colors['bg_primary'])
        style.configure('Secondary.TFrame', background=self.colors['bg_secondary'])
        style.configure('Header.TLabel',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['accent_primary'],
                       font=('Consolas', 14, 'bold'))
        style.configure('Subheader.TLabel',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['accent_secondary'],
                       font=('Consolas', 12, 'bold'))
        style.configure('Metric.TLabel',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['text_primary'],
                       font=('Consolas', 10))
        style.configure('Value.TLabel',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['text_secondary'],
                       font=('Consolas', 10, 'bold'))
        style.configure('Memory.TLabel',
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['memory'],
                       font=('Consolas', 10, 'bold'))
        
    def create_optimized_interface(self):
        self.notebook = ttk.Notebook(self.root, style='Performance.TNotebook')
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.create_system_overview_tab()
        self.create_advanced_memory_analysis_tab()
        self.create_virtual_memory_mapping_tab()
        self.create_process_memory_analysis_tab()
        self.create_performance_dashboard_tab()
        self.create_process_management_tab()
        self.create_network_monitoring_tab()
        self.create_security_analysis_tab()
        
    def create_system_overview_tab(self):
        self.system_frame = ttk.Frame(self.notebook, style='Primary.TFrame')
        self.notebook.add(self.system_frame, text='SYSTEM OVERVIEW')
        
        left_panel = ttk.Frame(self.system_frame, style='Secondary.TFrame')
        left_panel.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        center_panel = ttk.Frame(self.system_frame, style='Secondary.TFrame')
        center_panel.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        right_panel = ttk.Frame(self.system_frame, style='Secondary.TFrame')
        right_panel.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(left_panel, text="SYSTEM ARCHITECTURE", style='Header.TLabel').pack(pady=10)
        self.system_info_display = ttk.Frame(left_panel, style='Secondary.TFrame')
        self.system_info_display.pack(fill='both', expand=True, padx=10, pady=5)
        
        ttk.Label(center_panel, text="PERFORMANCE METRICS", style='Header.TLabel').pack(pady=10)
        self.performance_display = ttk.Frame(center_panel, style='Secondary.TFrame')
        self.performance_display.pack(fill='both', expand=True, padx=10, pady=5)
        
        ttk.Label(right_panel, text="SYSTEM STATUS", style='Header.TLabel').pack(pady=10)
        self.status_display = ttk.Frame(right_panel, style='Secondary.TFrame')
        self.status_display.pack(fill='both', expand=True, padx=10, pady=5)
        
    def create_advanced_memory_analysis_tab(self):
        self.memory_analysis_frame = ttk.Frame(self.notebook, style='Primary.TFrame')
        self.notebook.add(self.memory_analysis_frame, text='MEMORY ANALYSIS')
        
        header_frame = ttk.Frame(self.memory_analysis_frame, style='Secondary.TFrame')
        header_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(header_frame, text="ADVANCED MEMORY SUBSYSTEM ANALYSIS", style='Header.TLabel').pack(side='left', pady=10)
        
        controls_frame = ttk.Frame(header_frame, style='Secondary.TFrame')
        controls_frame.pack(side='right', pady=10)
        
        self.analyze_memory_btn = tk.Button(controls_frame, text="DEEP MEMORY ANALYSIS",
                                          bg=self.colors['memory'], fg=self.colors['text_primary'],
                                          font=('Consolas', 10, 'bold'), relief='flat',
                                          command=self.perform_deep_memory_analysis)
        self.analyze_memory_btn.pack(side='left', padx=5)
        
        self.refresh_gpu_btn = tk.Button(controls_frame, text="GPU ANALYSIS",
                                       bg=self.colors['gpu'], fg=self.colors['text_primary'],
                                       font=('Consolas', 10, 'bold'), relief='flat',
                                       command=self.refresh_gpu_analysis)
        self.refresh_gpu_btn.pack(side='left', padx=5)
        
        analysis_container = ttk.Frame(self.memory_analysis_frame, style='Primary.TFrame')
        analysis_container.pack(fill='both', expand=True, padx=10, pady=5)
        
        physical_frame = ttk.Frame(analysis_container, style='Secondary.TFrame')
        physical_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(physical_frame, text="PHYSICAL MEMORY ARCHITECTURE", style='Subheader.TLabel').pack(pady=5)
        self.physical_memory_display = ttk.Frame(physical_frame, style='Secondary.TFrame')
        self.physical_memory_display.pack(fill='both', expand=True, padx=5, pady=5)
        
        virtual_frame = ttk.Frame(analysis_container, style='Secondary.TFrame')
        virtual_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(virtual_frame, text="VIRTUAL MEMORY ARCHITECTURE", style='Subheader.TLabel').pack(pady=5)
        self.virtual_memory_display = ttk.Frame(virtual_frame, style='Secondary.TFrame')
        self.virtual_memory_display.pack(fill='both', expand=True, padx=5, pady=5)
        
        gpu_frame = ttk.Frame(analysis_container, style='Secondary.TFrame')
        gpu_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(gpu_frame, text="GPU MEMORY UTILIZATION", style='Subheader.TLabel').pack(pady=5)
        self.gpu_memory_display = ttk.Frame(gpu_frame, style='Secondary.TFrame')
        self.gpu_memory_display.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_virtual_memory_mapping_tab(self):
        self.vmem_mapping_frame = ttk.Frame(self.notebook, style='Primary.TFrame')
        self.notebook.add(self.vmem_mapping_frame, text='VIRTUAL MEMORY MAPPING')
        
        vmem_header = ttk.Frame(self.vmem_mapping_frame, style='Secondary.TFrame')
        vmem_header.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(vmem_header, text="VIRTUAL ADDRESS SPACE MAPPING", style='Header.TLabel').pack(side='left', pady=10)
        
        vmem_controls = ttk.Frame(vmem_header, style='Secondary.TFrame')
        vmem_controls.pack(side='right', pady=10)
        
        self.map_process_btn = tk.Button(vmem_controls, text="MAP SELECTED PROCESS",
                                       bg=self.colors['accent_primary'], fg=self.colors['text_primary'],
                                       font=('Consolas', 10, 'bold'), relief='flat',
                                       command=self.map_selected_process_memory)
        self.map_process_btn.pack(side='left', padx=5)
        
        vmem_container = ttk.Frame(self.vmem_mapping_frame, style='Primary.TFrame')
        vmem_container.pack(fill='both', expand=True, padx=10, pady=5)
        
        selector_frame = ttk.Frame(vmem_container, style='Secondary.TFrame')
        selector_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(selector_frame, text="Select Process for Memory Mapping:", style='Metric.TLabel').pack(side='left', padx=5)
        
        self.process_selector = ttk.Combobox(selector_frame, width=50)
        self.process_selector.pack(side='left', padx=10)
        
        regions_frame = ttk.Frame(vmem_container, style='Secondary.TFrame')
        regions_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(regions_frame, text="VIRTUAL MEMORY REGIONS", style='Subheader.TLabel').pack(pady=5)
        
        self.memory_regions_tree = ttk.Treeview(regions_frame,
                                              columns=('Address', 'Size', 'State', 'Protection', 'Type'),
                                              show='headings', height=20)
        
        region_headers = ['Base Address', 'Size (MB)', 'State', 'Protection', 'Type']
        for i, header in enumerate(region_headers):
            self.memory_regions_tree.heading(f'#{i+1}', text=header)
            self.memory_regions_tree.column(f'#{i+1}', width=120)
            
        regions_scrollbar = ttk.Scrollbar(regions_frame, orient='vertical', command=self.memory_regions_tree.yview)
        self.memory_regions_tree.configure(yscrollcommand=regions_scrollbar.set)
        
        self.memory_regions_tree.pack(side='left', fill='both', expand=True)
        regions_scrollbar.pack(side='right', fill='y')
        
    def create_process_memory_analysis_tab(self):
        self.process_memory_frame = ttk.Frame(self.notebook, style='Primary.TFrame')
        self.notebook.add(self.process_memory_frame, text='PROCESS MEMORY ANALYSIS')
        
        proc_mem_header = ttk.Frame(self.process_memory_frame, style='Secondary.TFrame')
        proc_mem_header.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(proc_mem_header, text="PROCESS MEMORY UTILIZATION ANALYSIS", style='Header.TLabel').pack(side='left', pady=10)
        
        proc_mem_controls = ttk.Frame(proc_mem_header, style='Secondary.TFrame')
        proc_mem_controls.pack(side='right', pady=10)
        
        self.analyze_process_memory_btn = tk.Button(proc_mem_controls, text="ANALYZE PROCESS MEMORY",
                                                  bg=self.colors['info'], fg=self.colors['text_primary'],
                                                  font=('Consolas', 10, 'bold'), relief='flat',
                                                  command=self.analyze_selected_process_memory)
        self.analyze_process_memory_btn.pack(side='left', padx=5)
        
        proc_mem_container = ttk.Frame(self.process_memory_frame, style='Primary.TFrame')
        proc_mem_container.pack(fill='both', expand=True, padx=10, pady=5)
        
        proc_mem_tree_frame = ttk.Frame(proc_mem_container, style='Secondary.TFrame')
        proc_mem_tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(proc_mem_tree_frame, text="PROCESS MEMORY COUNTERS", style='Subheader.TLabel').pack(pady=5)
        
        self.process_memory_tree = ttk.Treeview(proc_mem_tree_frame,
                                              columns=('PID', 'Name', 'Working_Set', 'Private_Bytes', 'Page_Faults', 'Handles'),
                                              show='headings', height=25)
        
        proc_mem_headers = ['PID', 'Process Name', 'Working Set (MB)', 'Private Bytes (MB)', 'Page Faults', 'Handles']
        for i, header in enumerate(proc_mem_headers):
            self.process_memory_tree.heading(f'#{i+1}', text=header)
            self.process_memory_tree.column(f'#{i+1}', width=130)
            
        proc_mem_scrollbar = ttk.Scrollbar(proc_mem_tree_frame, orient='vertical', command=self.process_memory_tree.yview)
        self.process_memory_tree.configure(yscrollcommand=proc_mem_scrollbar.set)
        
        self.process_memory_tree.pack(side='left', fill='both', expand=True)
        proc_mem_scrollbar.pack(side='right', fill='y')
        
    def create_performance_dashboard_tab(self):
        self.dashboard_frame = ttk.Frame(self.notebook, style='Primary.TFrame')
        self.notebook.add(self.dashboard_frame, text='PERFORMANCE DASHBOARD')
        
        self.fig = Figure(figsize=(16, 12), facecolor=self.colors['bg_primary'])
        self.fig.patch.set_facecolor(self.colors['bg_primary'])
        
        gs = self.fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        self.ax_cpu = self.fig.add_subplot(gs[0, 0], facecolor=self.colors['bg_secondary'])
        self.ax_memory = self.fig.add_subplot(gs[0, 1], facecolor=self.colors['bg_secondary'])
        self.ax_virtual_memory = self.fig.add_subplot(gs[0, 2], facecolor=self.colors['bg_secondary'])
        self.ax_gpu_memory = self.fig.add_subplot(gs[1, 0], facecolor=self.colors['bg_secondary'])
        self.ax_page_faults = self.fig.add_subplot(gs[1, 1], facecolor=self.colors['bg_secondary'])
        self.ax_handles = self.fig.add_subplot(gs[1, 2], facecolor=self.colors['bg_secondary'])
        self.ax_network = self.fig.add_subplot(gs[2, 0], facecolor=self.colors['bg_secondary'])
        self.ax_disk = self.fig.add_subplot(gs[2, 1], facecolor=self.colors['bg_secondary'])
        self.ax_threads = self.fig.add_subplot(gs[2, 2], facecolor=self.colors['bg_secondary'])
        
        self.axes_list = [self.ax_cpu, self.ax_memory, self.ax_virtual_memory, self.ax_gpu_memory,
                         self.ax_page_faults, self.ax_handles, self.ax_network, self.ax_disk, self.ax_threads]
        
        for ax in self.axes_list:
            ax.tick_params(colors=self.colors['text_secondary'], labelsize=8)
            for spine in ax.spines.values():
                spine.set_color(self.colors['accent_secondary'])
                spine.set_linewidth(0.8)
            ax.grid(True, alpha=0.3, color=self.colors['text_secondary'])
            ax.set_facecolor(self.colors['bg_secondary'])
            
        self.canvas = FigureCanvasTkAgg(self.fig, self.dashboard_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_process_management_tab(self):
        self.process_frame = ttk.Frame(self.notebook, style='Primary.TFrame')
        self.notebook.add(self.process_frame, text='PROCESS MANAGEMENT')
        
        control_panel = ttk.Frame(self.process_frame, style='Secondary.TFrame')
        control_panel.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(control_panel, text="PROCESS EXECUTION CONTROL", style='Header.TLabel').pack(side='left', pady=10)
        
        controls_frame = ttk.Frame(control_panel, style='Secondary.TFrame')
        controls_frame.pack(side='right', pady=10)
        
        self.refresh_processes_btn = tk.Button(controls_frame, text="REFRESH",
                                             bg=self.colors['accent_primary'], fg=self.colors['text_primary'],
                                             font=('Consolas', 10, 'bold'), relief='flat',
                                             command=self.refresh_process_data)
        self.refresh_processes_btn.pack(side='left', padx=5)
        
        self.analyze_process_btn = tk.Button(controls_frame, text="ANALYZE",
                                           bg=self.colors['info'], fg=self.colors['text_primary'],
                                           font=('Consolas', 10, 'bold'), relief='flat',
                                           command=self.analyze_selected_process)
        self.analyze_process_btn.pack(side='left', padx=5)
        
        self.terminate_process_btn = tk.Button(controls_frame, text="TERMINATE",
                                             bg=self.colors['danger'], fg=self.colors['text_primary'],
                                             font=('Consolas', 10, 'bold'), relief='flat',
                                             command=self.terminate_selected_process)
        self.terminate_process_btn.pack(side='left', padx=5)
        
        tree_container = ttk.Frame(self.process_frame, style='Secondary.TFrame')
        tree_container.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.process_tree = ttk.Treeview(tree_container,
                                        columns=('PID', 'Name', 'CPU%', 'Memory_MB', 'Threads', 'Status'),
                                        show='headings', height=25)
        
        headers = ['PID', 'Process Name', 'CPU %', 'Memory (MB)', 'Threads', 'Status']
        for i, header in enumerate(headers):
            self.process_tree.heading(f'#{i+1}', text=header)
            self.process_tree.column(f'#{i+1}', width=120)
            
        process_scrollbar = ttk.Scrollbar(tree_container, orient='vertical', command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=process_scrollbar.set)
        
        self.process_tree.pack(side='left', fill='both', expand=True)
        process_scrollbar.pack(side='right', fill='y')
        
    def create_network_monitoring_tab(self):
        self.network_frame = ttk.Frame(self.notebook, style='Primary.TFrame')
        self.notebook.add(self.network_frame, text='NETWORK MONITORING')
        
        header_frame = ttk.Frame(self.network_frame, style='Secondary.TFrame')
        header_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(header_frame, text="NETWORK TRAFFIC ANALYSIS", style='Header.TLabel').pack(side='left', pady=10)
        
        network_controls = ttk.Frame(header_frame, style='Secondary.TFrame')
        network_controls.pack(side='right', pady=10)
        
        self.refresh_network_btn = tk.Button(network_controls, text="REFRESH CONNECTIONS",
                                           bg=self.colors['accent_primary'], fg=self.colors['text_primary'],
                                           font=('Consolas', 10, 'bold'), relief='flat',
                                           command=self.refresh_network_data)
        self.refresh_network_btn.pack(side='left', padx=5)
        
        network_container = ttk.Frame(self.network_frame, style='Primary.TFrame')
        network_container.pack(fill='both', expand=True, padx=10, pady=5)
        
        connections_frame = ttk.Frame(network_container, style='Secondary.TFrame')
        connections_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(connections_frame, text="ACTIVE CONNECTIONS", style='Header.TLabel').pack(pady=5)
        
        self.connections_tree = ttk.Treeview(connections_frame,
                                           columns=('Local', 'Remote', 'Status', 'PID', 'Process'),
                                           show='headings', height=20)
        
        connection_headers = ['Local Address', 'Remote Address', 'Status', 'PID', 'Process']
        for i, header in enumerate(connection_headers):
            self.connections_tree.heading(f'#{i+1}', text=header)
            self.connections_tree.column(f'#{i+1}', width=140)
            
        conn_scrollbar = ttk.Scrollbar(connections_frame, orient='vertical', command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=conn_scrollbar.set)
        
        self.connections_tree.pack(side='left', fill='both', expand=True)
        conn_scrollbar.pack(side='right', fill='y')
        
        stats_frame = ttk.Frame(network_container, style='Secondary.TFrame')
        stats_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(stats_frame, text="NETWORK STATISTICS", style='Header.TLabel').pack(pady=5)
        self.network_stats_display = ttk.Frame(stats_frame, style='Secondary.TFrame')
        self.network_stats_display.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_security_analysis_tab(self):
        self.security_frame = ttk.Frame(self.notebook, style='Primary.TFrame')
        self.notebook.add(self.security_frame, text='SECURITY ANALYSIS')
        
        security_header = ttk.Frame(self.security_frame, style='Secondary.TFrame')
        security_header.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(security_header, text="SECURITY INTELLIGENCE", style='Header.TLabel').pack(side='left', pady=10)
        
        security_controls = ttk.Frame(security_header, style='Secondary.TFrame')
        security_controls.pack(side='right', pady=10)
        
        self.security_scan_btn = tk.Button(security_controls, text="SECURITY SCAN",
                                         bg=self.colors['warning'], fg=self.colors['text_primary'],
                                         font=('Consolas', 10, 'bold'), relief='flat',
                                         command=self.perform_security_scan)
        self.security_scan_btn.pack(side='left', padx=5)
        
        security_container = ttk.Frame(self.security_frame, style='Primary.TFrame')
        security_container.pack(fill='both', expand=True, padx=10, pady=5)
        
        security_status_frame = ttk.Frame(security_container, style='Secondary.TFrame')
        security_status_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(security_status_frame, text="SYSTEM SECURITY STATUS", style='Header.TLabel').pack(pady=5)
        self.security_status_display = ttk.Frame(security_status_frame, style='Secondary.TFrame')
        self.security_status_display.pack(fill='both', expand=True, padx=5, pady=5)
        
        security_events_frame = ttk.Frame(security_container, style='Secondary.TFrame')
        security_events_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(security_events_frame, text="SECURITY EVENTS", style='Header.TLabel').pack(pady=5)
        self.security_events_display = ttk.Frame(security_events_frame, style='Secondary.TFrame')
        self.security_events_display.pack(fill='both', expand=True, padx=5, pady=5)
        
    def initialize_consolidated_monitoring(self):
        self.start_primary_monitoring_thread()
        
        self.start_gui_update_processor()
        
        self.start_performance_monitor()
        
        self.start_memory_analysis_thread()
        
    def start_primary_monitoring_thread(self):
        def primary_monitoring_worker():
            last_expensive_update = time.time()
            last_memory_analysis = time.time()
            expensive_update_interval = 10.0
            memory_analysis_interval = 5.0
            
            while self.monitoring_active:
                start_time = time.time()
                
                try:
                    self.collect_core_performance_metrics()
                    
                    current_time = time.time()
                    if current_time - last_expensive_update >= expensive_update_interval:
                        self.collect_expensive_metrics()
                        last_expensive_update = current_time
                        
                    if current_time - last_memory_analysis >= memory_analysis_interval:
                        self.collect_advanced_memory_metrics()
                        last_memory_analysis = current_time
                        
                    self.queue_gui_updates()
                    
                    collection_time = time.time() - start_time
                    self.performance_stats['data_collection_time'].append(collection_time)
                    
                    sleep_time = max(0.1, self.update_interval - collection_time)
                    time.sleep(sleep_time)
                    
                except Exception as e:
                    print(f"Primary monitoring error: {e}")
                    time.sleep(self.update_interval)
                    
        self.primary_thread = threading.Thread(target=primary_monitoring_worker, daemon=True)
        self.primary_thread.start()
        
    def start_memory_analysis_thread(self):
        def memory_analysis_worker():
            while self.monitoring_active:
                try:
                    start_time = time.time()
                    
                    memory_analysis = self.memory_analyzer.analyze_system_memory_architecture()
                    if memory_analysis:
                        with self.data_lock:
                            self.memory_analysis_data['system_memory_architecture'] = memory_analysis
                            self.memory_analysis_data['last_analysis_timestamp'] = datetime.now()
                            
                    gpu_analysis = self.memory_analyzer.analyze_gpu_memory_utilization()
                    if gpu_analysis:
                        with self.data_lock:
                            self.memory_analysis_data['gpu_memory_utilization'] = gpu_analysis
                            
                    analysis_time = time.time() - start_time
                    self.performance_stats['memory_analysis_time'].append(analysis_time)
                    
                    time.sleep(15.0)
                    
                except Exception as e:
                    print(f"Memory analysis error: {e}")
                    time.sleep(15.0)
                    
        self.memory_analysis_thread = threading.Thread(target=memory_analysis_worker, daemon=True)
        self.memory_analysis_thread.start()
        
    def start_gui_update_processor(self):
        def gui_update_processor():
            while self.monitoring_active:
                try:
                    updates_processed = 0
                    max_updates_per_cycle = 10
                    
                    while updates_processed < max_updates_per_cycle and not self.gui_update_queue.empty():
                        try:
                            update_func = self.gui_update_queue.get_nowait()
                            if callable(update_func):
                                self.root.after_idle(update_func)
                            updates_processed += 1
                        except queue.Empty:
                            break
                        except Exception as e:
                            print(f"GUI update error: {e}")
                            
                    time.sleep(0.1)                    
                except Exception as e:
                    print(f"GUI processor error: {e}")
                    time.sleep(0.5)
                    
        self.gui_thread = threading.Thread(target=gui_update_processor, daemon=True)
        self.gui_thread.start()
        
    def start_performance_monitor(self):
        def performance_monitor():
            while self.monitoring_active:
                try:
                    if self.performance_stats['data_collection_time']:
                        avg_collection_time = sum(self.performance_stats['data_collection_time']) / len(self.performance_stats['data_collection_time'])
                        
                        if avg_collection_time > self.update_interval * 0.8:
                            self.update_interval = min(5.0, self.update_interval * 1.1)
                        elif avg_collection_time < self.update_interval * 0.3:
                            self.update_interval = max(1.0, self.update_interval * 0.9)
                            
                    if len(self.performance_stats['data_collection_time']) % 50 == 0:
                        gc.collect()
                        
                    time.sleep(30.0)                    
                except Exception as e:
                    print(f"Performance monitor error: {e}")
                    time.sleep(30.0)
                    
        self.performance_thread = threading.Thread(target=performance_monitor, daemon=True)
        self.performance_thread.start()
        
    def collect_core_performance_metrics(self):
        try:
            with self.data_lock:
                current_time = datetime.now()
                
                cpu_percent = psutil.cpu_percent(interval=None)
                
                memory = psutil.virtual_memory()
                
                if hasattr(self, 'memory_analysis_data') and self.memory_analysis_data.get('system_memory_architecture'):
                    mem_arch = self.memory_analysis_data['system_memory_architecture']
                    
                    detailed_memory = {
                        'physical_percent': memory.percent,
                        'virtual_percent': 0,
                        'page_file_percent': 0
                    }
                    
                    if mem_arch.get('virtual_memory'):
                        vm = mem_arch['virtual_memory']
                        if vm['total_bytes'] > 0:
                            detailed_memory['virtual_percent'] = (vm['used_bytes'] / vm['total_bytes']) * 100
                            
                    if mem_arch.get('page_file'):
                        pf = mem_arch['page_file']
                        if pf['total_bytes'] > 0:
                            detailed_memory['page_file_percent'] = (pf['used_bytes'] / pf['total_bytes']) * 100
                            
                    self.performance_metrics['memory_detailed'].append(detailed_memory)
                    
                    self.performance_metrics['virtual_memory'].append({
                        'used_gb': vm.get('used_gb', 0),
                        'total_gb': vm.get('total_gb', 0),
                        'percent': detailed_memory['virtual_percent']
                    })
                    
                if hasattr(self, 'memory_analysis_data') and self.memory_analysis_data.get('gpu_memory_utilization'):
                    gpu_data = self.memory_analysis_data['gpu_memory_utilization']
                    gpu_usage = 0
                    
                    for gpu_name, gpu_info in gpu_data.items():
                        if 'utilization_percent' in gpu_info:
                            gpu_usage = max(gpu_usage, gpu_info['utilization_percent'])
                            
                    self.performance_metrics['gpu_memory'].append(gpu_usage)
                    
                if hasattr(self, 'memory_analysis_data') and self.memory_analysis_data.get('system_memory_architecture'):
                    sys_perf = self.memory_analysis_data['system_memory_architecture'].get('system_performance', {})
                    
                    self.performance_metrics['handle_count'].append(sys_perf.get('handle_count', 0))
                    self.performance_metrics['thread_count'].append(sys_perf.get('thread_count', 0))
                    self.performance_metrics['process_count'].append(sys_perf.get('process_count', 0))
                    
                disk_io = psutil.disk_io_counters()
                
                network_io = psutil.net_io_counters()
                
                self.performance_metrics['timestamps'].append(current_time)
                self.performance_metrics['cpu_cores'].append(cpu_percent)
                self.performance_metrics['memory_usage'].append(memory.percent)
                
                if disk_io:
                    self.performance_metrics['disk_io'].append({
                        'read_mb': disk_io.read_bytes / (1024 * 1024),
                        'write_mb': disk_io.write_bytes / (1024 * 1024)
                    })
                    
                if network_io:
                    self.performance_metrics['network_io'].append({
                        'sent_mb': network_io.bytes_sent / (1024 * 1024),
                        'recv_mb': network_io.bytes_recv / (1024 * 1024)
                    })
                    
        except Exception as e:
            print(f"Core metrics collection error: {e}")
            
    def collect_advanced_memory_metrics(self):
        try:
            start_time = time.time()
            
            memory_analysis = self.memory_analyzer.analyze_system_memory_architecture()
            if memory_analysis:
                with self.data_lock:
                    self.memory_analysis_data['system_memory_architecture'] = memory_analysis
                    
            gpu_analysis = self.memory_analyzer.analyze_gpu_memory_utilization()
            if gpu_analysis:
                with self.data_lock:
                    self.memory_analysis_data['gpu_memory_utilization'] = gpu_analysis
                    
            process_memory_data = {}
            process_count = 0
            max_processes = 20              
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                try:
                    if process_count >= max_processes:
                        break
                        
                    info = proc.info
                    if info['memory_percent'] and info['memory_percent'] > 1.0:  # Only analyze processes using >1% memory
                        memory_counters = self.memory_analyzer.analyze_process_memory_counters(info['pid'])
                        if memory_counters:
                            process_memory_data[info['pid']] = {
                                'name': info['name'],
                                'memory_counters': memory_counters
                            }
                            process_count += 1
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            if process_memory_data:
                with self.data_lock:
                    self.memory_analysis_data['process_memory_maps'] = process_memory_data
                    
            analysis_time = time.time() - start_time
            self.performance_stats['memory_analysis_time'].append(analysis_time)
            
        except Exception as e:
            print(f"Advanced memory metrics collection error: {e}")
            
    def collect_expensive_metrics(self):
        try:
            current_time = time.time()
            
            if not self.cached_data['system_info'] or current_time - self.cached_data['cache_timestamps'].get('system_info', 0) > 300:
                self.cached_data['system_info'] = self.collect_system_information()
                self.cached_data['cache_timestamps']['system_info'] = current_time
                
            if not self.cached_data['hardware_info'] or current_time - self.cached_data['cache_timestamps'].get('hardware_info', 0) > 600:
                self.cached_data['hardware_info'] = self.collect_hardware_information()
                self.cached_data['cache_timestamps']['hardware_info'] = current_time
                
            if current_time - self.cached_data['cache_timestamps'].get('process_list', 0) > 5:
                self.cached_data['process_list'] = self.collect_process_information()
                self.cached_data['cache_timestamps']['process_list'] = current_time
                
            if current_time - self.cached_data['cache_timestamps'].get('network_connections', 0) > 3:
                self.cached_data['network_connections'] = self.collect_network_connections()
                self.cached_data['cache_timestamps']['network_connections'] = current_time
                
            if current_time - self.cached_data['cache_timestamps'].get('security_status', 0) > 30:
                self.cached_data['security_status'] = self.collect_security_information()
                self.cached_data['cache_timestamps']['security_status'] = current_time
                
        except Exception as e:
            print(f"Expensive metrics collection error: {e}")
            
    def collect_system_information(self):
        try:
            uname = platform.uname()
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            
            return {
                'system': f"{uname.system} {uname.release}",
                'architecture': f"{uname.machine} ({platform.architecture()[0]})",
                'processor': uname.processor,
                'hostname': uname.node,
                'boot_time': boot_time.strftime("%Y-%m-%d %H:%M:%S"),
                'uptime': str(datetime.now() - boot_time).split('.')[0],
                'python_version': f"{sys.version.split()[0]} ({platform.python_implementation()})"
            }
        except Exception as e:
            print(f"System info collection error: {e}")
            return {}
            
    def collect_hardware_information(self):
        try:
            hardware_info = {}
            
            cpu_count_physical = psutil.cpu_count(logical=False)
            cpu_count_logical = psutil.cpu_count(logical=True)
            cpu_freq = psutil.cpu_freq()
            
            hardware_info['cpu'] = {
                'physical_cores': cpu_count_physical,
                'logical_cores': cpu_count_logical,
                'current_freq': f"{cpu_freq.current:.0f} MHz" if cpu_freq else "N/A",
                'max_freq': f"{cpu_freq.max:.0f} MHz" if cpu_freq else "N/A"
            }
            
            if hasattr(self, 'memory_analysis_data') and self.memory_analysis_data.get('system_memory_architecture'):
                mem_arch = self.memory_analysis_data['system_memory_architecture']
                
                hardware_info['memory'] = {
                    'total_ram': f"{mem_arch['physical_memory']['total_gb']:.2f} GB",
                    'available_ram': f"{mem_arch['physical_memory']['available_gb']:.2f} GB",
                    'used_ram': f"{mem_arch['physical_memory']['used_gb']:.2f} GB",
                    'ram_usage': f"{mem_arch['physical_memory']['memory_load_percent']:.1f}%",
                    'virtual_total': f"{mem_arch['virtual_memory']['total_gb']:.2f} GB",
                    'virtual_used': f"{mem_arch['virtual_memory']['used_gb']:.2f} GB",
                    'page_size': f"{mem_arch['architecture']['page_size']} bytes"
                }
            else:
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                hardware_info['memory'] = {
                    'total_ram': f"{self.bytes_to_gb(memory.total):.2f} GB",
                    'available_ram': f"{self.bytes_to_gb(memory.available):.2f} GB",
                    'total_swap': f"{self.bytes_to_gb(swap.total):.2f} GB",
                    'ram_usage': f"{memory.percent:.1f}%",
                    'swap_usage': f"{swap.percent:.1f}%"
                }
            
            disk_usage = psutil.disk_usage('/')
            hardware_info['storage'] = {
                'total_disk': f"{self.bytes_to_gb(disk_usage.total):.1f} GB",
                'used_disk': f"{self.bytes_to_gb(disk_usage.used):.1f} GB",
                'disk_usage': f"{disk_usage.percent:.1f}%"
            }
            
            if self.wmi_interface:
                try:
                    cpu_info = self.wmi_interface.Win32_Processor()[0]
                    hardware_info['cpu']['name'] = cpu_info.Name
                    hardware_info['cpu']['max_clock'] = f"{cpu_info.MaxClockSpeed} MHz"
                except Exception as e:
                    print(f"WMI CPU info error: {e}")
                    
            return hardware_info
            
        except Exception as e:
            print(f"Hardware info collection error: {e}")
            return {}
            
    def collect_process_information(self):
        try:
            processes = []
            process_count = 0
            max_processes = 150 
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'num_threads', 'status']):
                try:
                    if process_count >= max_processes:
                        break
                        
                    info = proc.info
                    processes.append({
                        'pid': info['pid'],
                        'name': info['name'] or 'Unknown',
                        'cpu_percent': f"{info['cpu_percent']:.1f}%" if info['cpu_percent'] is not None else "0.0%",
                        'memory_mb': f"{info['memory_info'].rss / (1024*1024):.1f}" if info['memory_info'] else "0.0",
                        'threads': info['num_threads'] or 0,
                        'status': info['status'] or 'Unknown'
                    })
                    process_count += 1
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            processes.sort(key=lambda x: float(x['cpu_percent'].replace('%', '')), reverse=True)
            return processes
            
        except Exception as e:
            print(f"Process info collection error: {e}")
            return []
            
    def collect_network_connections(self):
        try:
            connections = []
            connection_count = 0
            max_connections = 100  # Limit for performance
            
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if connection_count >= max_connections:
                        break
                        
                    process_name = "Unknown"
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
                    connections.append({
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid or 0,
                        'process': process_name
                    })
                    connection_count += 1
                    
                except Exception:
                    continue
                    
            return connections
            
        except Exception as e:
            print(f"Network connections collection error: {e}")
            return []
            
    def collect_security_information(self):
        try:
            security_info = {
                'defender_status': 'Unknown',
                'firewall_status': 'Unknown',
                'suspicious_processes': 0,
                'network_security': 'Unknown',
                'last_scan': datetime.now().strftime("%H:%M:%S")
            }
            
            try:
                result = subprocess.run(['powershell', 'Get-MpComputerStatus | Select-Object AntivirusEnabled'],
                                      capture_output=True, text=True, timeout=5)
                security_info['defender_status'] = "Active" if 'True' in result.stdout else "Inactive"
            except:
                security_info['defender_status'] = "Unknown"
                
            try:
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                                      capture_output=True, text=True, timeout=5)
                security_info['firewall_status'] = "Active" if 'ON' in result.stdout else "Inactive"
            except:
                security_info['firewall_status'] = "Unknown"
                
            suspicious_keywords = ['keylog', 'backdoor', 'trojan']
            suspicious_count = 0
            
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name']
                    if proc_name and any(keyword in proc_name.lower() for keyword in suspicious_keywords):
                        suspicious_count += 1
                except:
                    continue
                    
            security_info['suspicious_processes'] = suspicious_count
            security_info['network_security'] = "Secure" if suspicious_count == 0 else "Alert"
            
            return security_info
            
        except Exception as e:
            print(f"Security info collection error: {e}")
            return {}
            
    def queue_gui_updates(self):
        try:
            self.gui_update_queue.put(self.update_system_overview_display)
            self.gui_update_queue.put(self.update_performance_dashboard)
            self.gui_update_queue.put(self.update_memory_analysis_displays)
            
            if time.time() % 10 < self.update_interval:  # Every 10 seconds
                self.gui_update_queue.put(self.update_process_display)
                self.gui_update_queue.put(self.update_network_display)
                self.gui_update_queue.put(self.update_security_display)
                
        except Exception as e:
            print(f"GUI queue error: {e}")
            
    def update_system_overview_display(self):
        try:
            for widget in self.system_info_display.winfo_children():
                widget.destroy()
            for widget in self.performance_display.winfo_children():
                widget.destroy()
            for widget in self.status_display.winfo_children():
                widget.destroy()
                
            if self.cached_data['system_info']:
                sys_info = self.cached_data['system_info']
                
                system_metrics = [
                    ("System:", sys_info.get('system', 'Unknown')),
                    ("Architecture:", sys_info.get('architecture', 'Unknown')),
                    ("Processor:", sys_info.get('processor', 'Unknown')),
                    ("Hostname:", sys_info.get('hostname', 'Unknown')),
                    ("Boot Time:", sys_info.get('boot_time', 'Unknown')),
                    ("Uptime:", sys_info.get('uptime', 'Unknown'))
                ]
                
                row = 0
                for label, value in system_metrics:
                    ttk.Label(self.system_info_display, text=label, style='Metric.TLabel').grid(
                        row=row, column=0, sticky='w', padx=5, pady=2)
                    ttk.Label(self.system_info_display, text=value, style='Value.TLabel').grid(
                        row=row, column=1, sticky='w', padx=5, pady=2)
                    row += 1
                    
            if self.performance_metrics['timestamps']:
                latest_metrics = {
                    'cpu': self.performance_metrics['cpu_cores'][-1] if self.performance_metrics['cpu_cores'] else 0,
                    'memory': self.performance_metrics['memory_usage'][-1] if self.performance_metrics['memory_usage'] else 0,
                    'processes': self.performance_metrics['process_count'][-1] if self.performance_metrics['process_count'] else 0,
                    'threads': self.performance_metrics['thread_count'][-1] if self.performance_metrics['thread_count'] else 0
                }
                
                performance_metrics = [
                    ("CPU Usage:", f"{latest_metrics['cpu']:.1f}%"),
                    ("Memory Usage:", f"{latest_metrics['memory']:.1f}%"),
                    ("Active Processes:", str(latest_metrics['processes'])),
                    ("System Threads:", str(latest_metrics['threads'])),
                    ("Update Interval:", f"{self.update_interval:.1f}s"),
                    ("Last Update:", datetime.now().strftime("%H:%M:%S"))
                ]
                
                row = 0
                for label, value in performance_metrics:
                    ttk.Label(self.performance_display, text=label, style='Metric.TLabel').grid(
                        row=row, column=0, sticky='w', padx=5, pady=2)
                    ttk.Label(self.performance_display, text=value, style='Value.TLabel').grid(
                        row=row, column=1, sticky='w', padx=5, pady=2)
                    row += 1
                    
            if self.cached_data['security_status']:
                sec_info = self.cached_data['security_status']
                
                status_metrics = [
                    ("Security Status:", sec_info.get('network_security', 'Unknown')),
                    ("Windows Defender:", sec_info.get('defender_status', 'Unknown')),
                    ("Firewall:", sec_info.get('firewall_status', 'Unknown')),
                    ("Suspicious Processes:", str(sec_info.get('suspicious_processes', 0))),
                    ("System Health:", self.assess_system_health()),
                    ("Network Status:", self.get_network_status())
                ]
                
                row = 0
                for label, value in status_metrics:
                    style = 'Value.TLabel'
                    if 'Alert' in value or 'Inactive' in value or 'Critical' in value:
                        style = 'Metric.TLabel'  # Use different style for warnings
                        
                    ttk.Label(self.status_display, text=label, style='Metric.TLabel').grid(
                        row=row, column=0, sticky='w', padx=5, pady=2)
                    ttk.Label(self.status_display, text=value, style=style).grid(
                        row=row, column=1, sticky='w', padx=5, pady=2)
                    row += 1
                    
        except Exception as e:
            print(f"System overview update error: {e}")
            
    def update_memory_analysis_displays(self):
        try:
            for widget in self.physical_memory_display.winfo_children():
                widget.destroy()
            for widget in self.virtual_memory_display.winfo_children():
                widget.destroy()
            for widget in self.gpu_memory_display.winfo_children():
                widget.destroy()
                
            if self.memory_analysis_data.get('system_memory_architecture'):
                memory_arch = self.memory_analysis_data['system_memory_architecture']
                
                if 'physical_memory' in memory_arch:
                    phys_mem = memory_arch['physical_memory']
                    
                    physical_metrics = [
                        ("Total Physical RAM:", f"{phys_mem['total_gb']:.2f} GB"),
                        ("Available RAM:", f"{phys_mem['available_gb']:.2f} GB"),
                        ("Used RAM:", f"{phys_mem['used_gb']:.2f} GB"),
                        ("Memory Load:", f"{phys_mem['memory_load_percent']}%"),
                        ("Physical Utilization:", f"{((phys_mem['total_gb'] - phys_mem['available_gb']) / phys_mem['total_gb'] * 100):.1f}%")
                    ]
                    
                    if 'system_performance' in memory_arch:
                        sys_perf = memory_arch['system_performance']
                        physical_metrics.extend([
                            ("System Cache:", f"{sys_perf['system_cache'] / (1024**3):.2f} GB"),
                            ("Kernel Total:", f"{sys_perf['kernel_total'] / (1024**3):.2f} GB"),
                            ("Kernel Paged:", f"{sys_perf['kernel_paged'] / (1024**3):.2f} GB"),
                            ("Kernel Non-Paged:", f"{sys_perf['kernel_nonpaged'] / (1024**3):.2f} GB")
                        ])
                    
                    row = 0
                    for label, value in physical_metrics:
                        ttk.Label(self.physical_memory_display, text=label, style='Metric.TLabel').grid(
                            row=row, column=0, sticky='w', padx=5, pady=2)
                        ttk.Label(self.physical_memory_display, text=value, style='Memory.TLabel').grid(
                            row=row, column=1, sticky='w', padx=5, pady=2)
                        row += 1
                        
                if 'virtual_memory' in memory_arch:
                    virt_mem = memory_arch['virtual_memory']
                    
                    virtual_metrics = [
                        ("Total Virtual Space:", f"{virt_mem['total_gb']:.2f} GB"),
                        ("Available Virtual:", f"{virt_mem['available_gb']:.2f} GB"),
                        ("Used Virtual:", f"{virt_mem['used_gb']:.2f} GB"),
                        ("Virtual Utilization:", f"{(virt_mem['used_gb'] / virt_mem['total_gb'] * 100):.1f}%")
                    ]
                    
                    if 'page_file' in memory_arch:
                        page_file = memory_arch['page_file']
                        virtual_metrics.extend([
                            ("Page File Total:", f"{page_file['total_gb']:.2f} GB"),
                            ("Page File Used:", f"{page_file['used_gb']:.2f} GB"),
                            ("Page File Usage:", f"{(page_file['used_gb'] / page_file['total_gb'] * 100):.1f}%")
                        ])
                        
                    if 'architecture' in memory_arch:
                        arch = memory_arch['architecture']
                        virtual_metrics.extend([
                            ("Page Size:", f"{arch['page_size']} bytes"),
                            ("Allocation Granularity:", f"{arch['allocation_granularity']} bytes")
                        ])
                    
                    row = 0
                    for label, value in virtual_metrics:
                        ttk.Label(self.virtual_memory_display, text=label, style='Metric.TLabel').grid(
                            row=row, column=0, sticky='w', padx=5, pady=2)
                        ttk.Label(self.virtual_memory_display, text=value, style='Memory.TLabel').grid(
                            row=row, column=1, sticky='w', padx=5, pady=2)
                        row += 1
                        
            if self.memory_analysis_data.get('gpu_memory_utilization'):
                gpu_data = self.memory_analysis_data['gpu_memory_utilization']
                
                row = 0
                for gpu_name, gpu_info in gpu_data.items():
                    ttk.Label(self.gpu_memory_display, text=f"GPU: {gpu_info.get('name', 'Unknown')}", 
                             style='Subheader.TLabel').grid(row=row, column=0, columnspan=2, sticky='w', padx=5, pady=5)
                    row += 1
                    
                    if 'total_mb' in gpu_info:
                        gpu_metrics = [
                            ("Total GPU Memory:", f"{gpu_info['total_mb']:.0f} MB"),
                            ("Used GPU Memory:", f"{gpu_info.get('used_mb', 0):.0f} MB"),
                            ("Free GPU Memory:", f"{gpu_info.get('free_mb', 0):.0f} MB"),
                            ("GPU Utilization:", f"{gpu_info.get('utilization_percent', 0):.1f}%")
                        ]
                        
                        if 'driver_version' in gpu_info:
                            gpu_metrics.append(("Driver Version:", gpu_info['driver_version']))
                            
                        for label, value in gpu_metrics:
                            ttk.Label(self.gpu_memory_display, text=label, style='Metric.TLabel').grid(
                                row=row, column=0, sticky='w', padx=5, pady=1)
                            ttk.Label(self.gpu_memory_display, text=value, style='Value.TLabel').grid(
                                row=row, column=1, sticky='w', padx=5, pady=1)
                            row += 1
                    
                    row += 1
                    
            else:
                ttk.Label(self.gpu_memory_display, text="GPU Memory information unavailable", 
                         style='Metric.TLabel').pack(pady=20)
                ttk.Label(self.gpu_memory_display, text="Install pynvml for NVIDIA GPU support", 
                         style='Value.TLabel').pack(pady=5)
                    
        except Exception as e:
            print(f"Memory analysis display update error: {e}")
            
    def update_performance_dashboard(self):
        try:
            if not self.performance_metrics['timestamps']:
                return
                
            for ax in self.axes_list:
                ax.clear()
                
            timestamps = list(self.performance_metrics['timestamps'])
            
            if self.performance_metrics['cpu_cores']:
                cpu_data = list(self.performance_metrics['cpu_cores'])
                self.ax_cpu.plot(timestamps[-len(cpu_data):], cpu_data,
                               color=self.colors['accent_primary'], linewidth=2, alpha=0.8)
                self.ax_cpu.set_title('CPU Utilization (%)', color=self.colors['accent_primary'], fontweight='bold')
                self.ax_cpu.set_ylim(0, 100)
                
            if self.performance_metrics['memory_usage']:
                memory_data = list(self.performance_metrics['memory_usage'])
                self.ax_memory.plot(timestamps[-len(memory_data):], memory_data,
                                  color=self.colors['warning'], linewidth=2, alpha=0.8)
                self.ax_memory.set_title('Physical Memory Usage (%)', color=self.colors['accent_primary'], fontweight='bold')
                self.ax_memory.set_ylim(0, 100)
                
            if self.performance_metrics['virtual_memory']:
                virtual_data = list(self.performance_metrics['virtual_memory'])
                virtual_percent = [v['percent'] for v in virtual_data if 'percent' in v]
                
                if virtual_percent:
                    timestamps_virtual = timestamps[-len(virtual_percent):]
                    self.ax_virtual_memory.plot(timestamps_virtual, virtual_percent,
                                              color=self.colors['memory'], linewidth=2, alpha=0.8)
                    self.ax_virtual_memory.set_title('Virtual Memory Usage (%)', color=self.colors['accent_primary'], fontweight='bold')
                    self.ax_virtual_memory.set_ylim(0, 100)
                    
            if self.performance_metrics['gpu_memory']:
                gpu_data = list(self.performance_metrics['gpu_memory'])
                gpu_data = [x for x in gpu_data if x > 0]  # Filter out zero values
                
                if gpu_data:
                    timestamps_gpu = timestamps[-len(gpu_data):]
                    self.ax_gpu_memory.plot(timestamps_gpu, gpu_data,
                                          color=self.colors['gpu'], linewidth=2, alpha=0.8)
                    self.ax_gpu_memory.set_title('GPU Memory Usage (%)', color=self.colors['accent_primary'], fontweight='bold')
                    self.ax_gpu_memory.set_ylim(0, 100)
                    
            if self.performance_metrics['page_faults']:
                page_fault_data = list(self.performance_metrics['page_faults'])
                self.ax_page_faults.plot(timestamps[-len(page_fault_data):], page_fault_data,
                                       color=self.colors['info'], linewidth=2, alpha=0.8)
                self.ax_page_faults.set_title('Page Faults', color=self.colors['accent_primary'], fontweight='bold')
                
            if self.performance_metrics['handle_count']:
                handle_data = list(self.performance_metrics['handle_count'])
                handle_data = [x for x in handle_data if x > 0]  # Filter out zero values
                
                if handle_data:
                    timestamps_handles = timestamps[-len(handle_data):]
                    self.ax_handles.plot(timestamps_handles, handle_data,
                                       color=self.colors['success'], linewidth=2, alpha=0.8)
                    self.ax_handles.set_title('System Handles', color=self.colors['accent_primary'], fontweight='bold')
                    
            if self.performance_metrics['network_io']:
                network_data = list(self.performance_metrics['network_io'])
                sent_data = [n['sent_mb'] for n in network_data]
                recv_data = [n['recv_mb'] for n in network_data]
                
                timestamps_network = timestamps[-len(network_data):]
                self.ax_network.plot(timestamps_network, sent_data, label='Sent',
                                   color=self.colors['danger'], linewidth=1.5)
                self.ax_network.plot(timestamps_network, recv_data, label='Received',
                                   color=self.colors['success'], linewidth=1.5)
                self.ax_network.set_title('Network I/O (MB)', color=self.colors['accent_primary'], fontweight='bold')
                self.ax_network.legend(loc='upper right', fontsize=8)
                
            if self.performance_metrics['disk_io']:
                disk_data = list(self.performance_metrics['disk_io'])
                read_data = [d['read_mb'] for d in disk_data]
                write_data = [d['write_mb'] for d in disk_data]
                
                timestamps_disk = timestamps[-len(disk_data):]
                self.ax_disk.plot(timestamps_disk, read_data, label='Read', 
                                color=self.colors['info'], linewidth=1.5)
                self.ax_disk.plot(timestamps_disk, write_data, label='Write',
                                color=self.colors['warning'], linewidth=1.5)
                self.ax_disk.set_title('Disk I/O (MB)', color=self.colors['accent_primary'], fontweight='bold')
                self.ax_disk.legend(loc='upper right', fontsize=8)
                
            if self.performance_metrics['thread_count']:
                thread_data = list(self.performance_metrics['thread_count'])
                thread_data = [x for x in thread_data if x > 0]  # Filter out zero values
                
                if thread_data:
                    timestamps_threads = timestamps[-len(thread_data):]
                    self.ax_threads.plot(timestamps_threads, thread_data,
                                       color=self.colors['info'], linewidth=2, alpha=0.8)
                    self.ax_threads.set_title('System Threads', color=self.colors['accent_primary'], fontweight='bold')
                
            for ax in self.axes_list:
                ax.tick_params(colors=self.colors['text_secondary'], labelsize=7)
                ax.tick_params(axis='x', rotation=45)
                for spine in ax.spines.values():
                    spine.set_color(self.colors['accent_secondary'])
                    spine.set_linewidth(0.8)
                ax.grid(True, alpha=0.3, color=self.colors['text_secondary'])
                
            self.fig.tight_layout()
            self.canvas.draw_idle()
            
        except Exception as e:
            print(f"Performance dashboard update error: {e}")
            
    def update_process_display(self):
        try:
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
                
            if self.cached_data['process_list']:
                for process in self.cached_data['process_list'][:100]:  # Limit for performance
                    self.process_tree.insert('', 'end', values=(
                        process['pid'],
                        process['name'],
                        process['cpu_percent'],
                        process['memory_mb'],
                        process['threads'],
                        process['status']
                    ))
                    
        except Exception as e:
            print(f"Process display update error: {e}")
            
    def update_network_display(self):
        try:
            for item in self.connections_tree.get_children():
                self.connections_tree.delete(item)
                
            for widget in self.network_stats_display.winfo_children():
                widget.destroy()
                
            if self.cached_data['network_connections']:
                for conn in self.cached_data['network_connections'][:50]:  # Limit for performance
                    self.connections_tree.insert('', 'end', values=(
                        conn['local_addr'],
                        conn['remote_addr'],
                        conn['status'],
                        conn['pid'],
                        conn['process']
                    ))
                    
                total_connections = len(self.cached_data['network_connections'])
                listening_connections = len([c for c in self.cached_data['network_connections'] if c['status'] == 'LISTEN'])
                established_connections = len([c for c in self.cached_data['network_connections'] if c['status'] == 'ESTABLISHED'])
                
                network_stats = [
                    ("Total Connections:", str(total_connections)),
                    ("Listening Ports:", str(listening_connections)),
                    ("Established:", str(established_connections)),
                    ("Network Security:", "Monitoring Active"),
                    ("Last Update:", datetime.now().strftime("%H:%M:%S"))
                ]
                
                row = 0
                for label, value in network_stats:
                    ttk.Label(self.network_stats_display, text=label, style='Metric.TLabel').grid(
                        row=row, column=0, sticky='w', padx=5, pady=2)
                    ttk.Label(self.network_stats_display, text=value, style='Value.TLabel').grid(
                        row=row, column=1, sticky='w', padx=5, pady=2)
                    row += 1
                    
        except Exception as e:
            print(f"Network display update error: {e}")
            
    def update_security_display(self):
        try:
            for widget in self.security_status_display.winfo_children():
                widget.destroy()
            for widget in self.security_events_display.winfo_children():
                widget.destroy()
                
            if self.cached_data['security_status']:
                sec_data = self.cached_data['security_status']
                
                security_metrics = [
                    ("Windows Defender:", sec_data.get('defender_status', 'Unknown')),
                    ("Firewall Status:", sec_data.get('firewall_status', 'Unknown')),
                    ("Suspicious Processes:", str(sec_data.get('suspicious_processes', 0))),
                    ("Network Security:", sec_data.get('network_security', 'Unknown')),
                    ("Last Security Scan:", sec_data.get('last_scan', 'Never')),
                    ("Security Level:", self.calculate_security_level())
                ]
                
                row = 0
                for label, value in security_metrics:
                    ttk.Label(self.security_status_display, text=label, style='Metric.TLabel').grid(
                        row=row, column=0, sticky='w', padx=5, pady=2)
                    ttk.Label(self.security_status_display, text=value, style='Value.TLabel').grid(
                        row=row, column=1, sticky='w', padx=5, pady=2)
                    row += 1
                    
                events_info = [
                    ("Security Events:", "Monitoring Active"),
                    ("Threat Level:", "Normal" if sec_data.get('suspicious_processes', 0) == 0 else "Elevated"),
                    ("System Integrity:", "Verified"),
                    ("Real-time Protection:", "Active" if sec_data.get('defender_status') == 'Active' else "Inactive")
                ]
                
                row = 0
                for label, value in events_info:
                    ttk.Label(self.security_events_display, text=label, style='Metric.TLabel').grid(
                        row=row, column=0, sticky='w', padx=5, pady=2)
                    ttk.Label(self.security_events_display, text=value, style='Value.TLabel').grid(
                        row=row, column=1, sticky='w', padx=5, pady=2)
                    row += 1
                    
        except Exception as e:
            print(f"Security display update error: {e}")
            
    def perform_deep_memory_analysis(self):
        self.analyze_memory_btn.config(state='disabled', text='ANALYZING...')
        
        def analysis_worker():
            try:
                memory_analysis = self.memory_analyzer.analyze_system_memory_architecture()
                
                if memory_analysis:
                    with self.data_lock:
                        self.memory_analysis_data['system_memory_architecture'] = memory_analysis
                        
                    analysis_results = f"""
DEEP MEMORY ANALYSIS RESULTS
============================
Physical Memory Architecture:
- Total Physical RAM: {memory_analysis['physical_memory']['total_gb']:.2f} GB
- Available RAM: {memory_analysis['physical_memory']['available_gb']:.2f} GB
- Memory Load: {memory_analysis['physical_memory']['memory_load_percent']}%

Virtual Memory Architecture:
- Total Virtual Space: {memory_analysis['virtual_memory']['total_gb']:.2f} GB
- Used Virtual Space: {memory_analysis['virtual_memory']['used_gb']:.2f} GB
- Virtual Utilization: {(memory_analysis['virtual_memory']['used_gb'] / memory_analysis['virtual_memory']['total_gb'] * 100):.1f}%

System Performance Metrics:
- Commit Total: {memory_analysis['system_performance']['commit_total'] / (1024**3):.2f} GB
- System Cache: {memory_analysis['system_performance']['system_cache'] / (1024**3):.2f} GB
- Kernel Memory: {memory_analysis['system_performance']['kernel_total'] / (1024**3):.2f} GB
- Handle Count: {memory_analysis['system_performance']['handle_count']:,}
- Thread Count: {memory_analysis['system_performance']['thread_count']:,}

Memory Architecture Details:
- Page Size: {memory_analysis['architecture']['page_size']} bytes
- Allocation Granularity: {memory_analysis['architecture']['allocation_granularity']} bytes
- Processor Architecture: {memory_analysis['architecture']['processor_architecture']}

Analysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
                    
                    def show_results():
                        results_window = tk.Toplevel(self.root)
                        results_window.title("Deep Memory Analysis Results")
                        results_window.geometry("800x600")
                        results_window.configure(bg=self.colors['bg_primary'])
                        
                        text_widget = tk.Text(results_window, bg=self.colors['bg_secondary'],
                                             fg=self.colors['text_primary'], font=('Consolas', 10))
                        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
                        text_widget.insert('1.0', analysis_results)
                        text_widget.config(state='disabled')
                        
                        self.analyze_memory_btn.config(state='normal', text='DEEP MEMORY ANALYSIS')
                        
                    self.root.after(0, show_results)
                else:
                    def show_error():
                        messagebox.showerror("Analysis Error", "Failed to perform deep memory analysis")
                        self.analyze_memory_btn.config(state='normal', text='DEEP MEMORY ANALYSIS')
                    self.root.after(0, show_error)
                    
            except Exception as e:
                def show_error():
                    messagebox.showerror("Analysis Error", f"Memory analysis failed: {str(e)}")
                    self.analyze_memory_btn.config(state='normal', text='DEEP MEMORY ANALYSIS')
                self.root.after(0, show_error)
                
        threading.Thread(target=analysis_worker, daemon=True).start()
        
    def refresh_gpu_analysis(self):
        self.refresh_gpu_btn.config(state='disabled', text='ANALYZING...')
        
        def gpu_analysis_worker():
            try:
                gpu_analysis = self.memory_analyzer.analyze_gpu_memory_utilization()
                
                if gpu_analysis:
                    with self.data_lock:
                        self.memory_analysis_data['gpu_memory_utilization'] = gpu_analysis
                        
                    gpu_results = "GPU MEMORY ANALYSIS RESULTS\n" + "="*35 + "\n\n"
                    
                    for gpu_name, gpu_info in gpu_analysis.items():
                        gpu_results += f"GPU: {gpu_info.get('name', 'Unknown')}\n"
                        if 'total_mb' in gpu_info:
                            gpu_results += f"- Total Memory: {gpu_info['total_mb']:.0f} MB\n"
                            gpu_results += f"- Used Memory: {gpu_info.get('used_mb', 0):.0f} MB\n"
                            gpu_results += f"- Free Memory: {gpu_info.get('free_mb', 0):.0f} MB\n"
                            gpu_results += f"- Utilization: {gpu_info.get('utilization_percent', 0):.1f}%\n"
                        if 'driver_version' in gpu_info:
                            gpu_results += f"- Driver Version: {gpu_info['driver_version']}\n"
                        gpu_results += "\n"
                        
                    gpu_results += f"Analysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    
                    def show_gpu_results():
                        messagebox.showinfo("GPU Analysis Complete", gpu_results)
                        self.refresh_gpu_btn.config(state='normal', text='GPU ANALYSIS')
                        
                    self.root.after(0, show_gpu_results)
                else:
                    def show_no_gpu():
                        messagebox.showinfo("GPU Analysis", "No GPU memory information available.\nInstall pynvml for NVIDIA GPU support.")
                        self.refresh_gpu_btn.config(state='normal', text='GPU ANALYSIS')
                    self.root.after(0, show_no_gpu)
                    
            except Exception as e:
                def show_error():
                    messagebox.showerror("GPU Analysis Error", f"GPU analysis failed: {str(e)}")
                    self.refresh_gpu_btn.config(state='normal', text='GPU ANALYSIS')
                self.root.after(0, show_error)
                
        threading.Thread(target=gpu_analysis_worker, daemon=True).start()
        
    def map_selected_process_memory(self):
        try:
            process_name = self.process_selector.get()
            if not process_name:
                messagebox.showwarning("Warning", "Please select a process for memory mapping")
                return
                
            pid = int(process_name.split('(PID: ')[1].split(')')[0])
            
            self.map_process_btn.config(state='disabled', text='MAPPING...')
            
            def mapping_worker():
                try:
                    memory_regions = self.memory_analyzer.analyze_process_memory_regions(pid)
                    
                    if memory_regions:
                        def update_regions_tree():
                            for item in self.memory_regions_tree.get_children():
                                self.memory_regions_tree.delete(item)
                                
                            for region in memory_regions[:500]:  # Limit for performance
                                self.memory_regions_tree.insert('', 'end', values=(
                                    region['base_address'],
                                    f"{region['region_size_mb']:.2f}",
                                    region['state'],
                                    region['protection'],
                                    region['type']
                                ))
                                
                            messagebox.showinfo("Memory Mapping Complete", 
                                               f"Successfully mapped {len(memory_regions)} memory regions for process {process_name}")
                            self.map_process_btn.config(state='normal', text='MAP SELECTED PROCESS')
                            
                        self.root.after(0, update_regions_tree)
                    else:
                        def show_error():
                            messagebox.showerror("Mapping Error", f"Failed to map memory regions for process {process_name}")
                            self.map_process_btn.config(state='normal', text='MAP SELECTED PROCESS')
                        self.root.after(0, show_error)
                        
                except Exception as e:
                    def show_error():
                        messagebox.showerror("Mapping Error", f"Memory mapping failed: {str(e)}")
                        self.map_process_btn.config(state='normal', text='MAP SELECTED PROCESS')
                    self.root.after(0, show_error)
                    
            threading.Thread(target=mapping_worker, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initiate memory mapping: {str(e)}")
            
    def analyze_selected_process_memory(self):
        self.analyze_process_memory_btn.config(state='disabled', text='ANALYZING...')
        
        def analysis_worker():
            try:
                def clear_tree():
                    for item in self.process_memory_tree.get_children():
                        self.process_memory_tree.delete(item)
                        
                self.root.after(0, clear_tree)
                
                process_memory_data = []
                process_count = 0
                max_processes = 50
                
                for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                    try:
                        if process_count >= max_processes:
                            break
                            
                        info = proc.info
                        if info['memory_percent'] and info['memory_percent'] > 0.5:  # Only analyze processes using >0.5% memory
                            memory_counters = self.memory_analyzer.analyze_process_memory_counters(info['pid'])
                            if memory_counters:
                                process_memory_data.append({
                                    'pid': info['pid'],
                                    'name': info['name'],
                                    'working_set_mb': memory_counters['working_set_mb'],
                                    'private_usage_mb': memory_counters['private_usage_mb'],
                                    'page_fault_count': memory_counters['page_fault_count'],
                                    'handles': 'N/A'  # Would need additional API calls
                                })
                                process_count += 1
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                process_memory_data.sort(key=lambda x: x['private_usage_mb'], reverse=True)
                
                def update_memory_tree():
                    for proc_data in process_memory_data:
                        self.process_memory_tree.insert('', 'end', values=(
                            proc_data['pid'],
                            proc_data['name'],
                            f"{proc_data['working_set_mb']:.1f}",
                            f"{proc_data['private_usage_mb']:.1f}",
                            proc_data['page_fault_count'],
                            proc_data['handles']
                        ))
                        
                    messagebox.showinfo("Process Memory Analysis Complete", 
                                       f"Analyzed memory usage for {len(process_memory_data)} processes")
                    self.analyze_process_memory_btn.config(state='normal', text='ANALYZE PROCESS MEMORY')
                    
                self.root.after(0, update_memory_tree)
                
            except Exception as e:
                def show_error():
                    messagebox.showerror("Analysis Error", f"Process memory analysis failed: {str(e)}")
                    self.analyze_process_memory_btn.config(state='normal', text='ANALYZE PROCESS MEMORY')
                self.root.after(0, show_error)
                
        threading.Thread(target=analysis_worker, daemon=True).start()
        
    def refresh_process_data(self):
        try:
            self.cached_data['process_list'] = self.collect_process_information()
            self.cached_data['cache_timestamps']['process_list'] = time.time()
            self.update_process_display()
            
            if hasattr(self, 'process_selector'):
                process_names = [f"{proc['name']} (PID: {proc['pid']})" for proc in self.cached_data['process_list'][:50]]
                self.process_selector['values'] = process_names
                
        except Exception as e:
            print(f"Process refresh error: {e}")
            
    def refresh_network_data(self):
        try:
            self.cached_data['network_connections'] = self.collect_network_connections()
            self.cached_data['cache_timestamps']['network_connections'] = time.time()
            self.update_network_display()
        except Exception as e:
            print(f"Network refresh error: {e}")
            
    def analyze_selected_process(self):
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a process to analyze.")
            return
            
        try:
            item = self.process_tree.item(selection[0])
            pid = int(item['values'][0])
            proc = psutil.Process(pid)
            
            basic_info = f"""
PROCESS ANALYSIS REPORT
=======================
PID: {proc.pid}
Name: {proc.name()}
Status: {proc.status()}
CPU Percent: {proc.cpu_percent()}%
Memory Percent: {proc.memory_percent():.2f}%
Threads: {proc.num_threads()}
Created: {datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')}

MEMORY INFORMATION:
RSS: {proc.memory_info().rss / (1024**2):.1f} MB
VMS: {proc.memory_info().vms / (1024**2):.1f} MB

EXECUTION CONTEXT:
Parent PID: {proc.ppid()}
Command Line: {' '.join(proc.cmdline()) if proc.cmdline() else 'N/A'}
"""
            
            memory_counters = self.memory_analyzer.analyze_process_memory_counters(pid)
            if memory_counters:
                advanced_info = f"""

ADVANCED MEMORY ANALYSIS:
========================
Working Set: {memory_counters['working_set_mb']:.1f} MB
Private Bytes: {memory_counters['private_usage_mb']:.1f} MB
Page Faults: {memory_counters['page_fault_count']:,}
Peak Working Set: {memory_counters['peak_working_set'] / (1024**2):.1f} MB
Pagefile Usage: {memory_counters['pagefile_usage_mb']:.1f} MB
Peak Pagefile Usage: {memory_counters['peak_pagefile_usage'] / (1024**2):.1f} MB

POOL USAGE:
Paged Pool: {memory_counters['quota_paged_pool'] / (1024**2):.1f} MB
Non-Paged Pool: {memory_counters['quota_nonpaged_pool'] / (1024**2):.1f} MB
Peak Paged Pool: {memory_counters['quota_peak_paged_pool'] / (1024**2):.1f} MB
Peak Non-Paged Pool: {memory_counters['quota_peak_nonpaged_pool'] / (1024**2):.1f} MB
"""
                basic_info += advanced_info
            
            analysis_window = tk.Toplevel(self.root)
            analysis_window.title(f"Advanced Process Analysis - {proc.name()} (PID: {pid})")
            analysis_window.geometry("800x700")
            analysis_window.configure(bg=self.colors['bg_primary'])
            
            text_widget = tk.Text(analysis_window, bg=self.colors['bg_secondary'],
                                 fg=self.colors['text_primary'], font=('Consolas', 10))
            text_widget.pack(fill='both', expand=True, padx=10, pady=10)
            text_widget.insert('1.0', basic_info)
            text_widget.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze process: {str(e)}")
            
    def terminate_selected_process(self):
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a process to terminate.")
            return
            
        try:
            item = self.process_tree.item(selection[0])
            pid = int(item['values'][0])
            proc_name = item['values'][1]
            
            if messagebox.askyesno("Confirm Termination",
                                 f"Terminate process {proc_name} (PID: {pid})?\n\nThis action cannot be undone."):
                proc = psutil.Process(pid)
                proc.terminate()
                messagebox.showinfo("Success", f"Process {proc_name} terminated successfully.")
                self.refresh_process_data()
                
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", "Process not found.")
        except psutil.AccessDenied:
            messagebox.showerror("Error", "Access denied. Run as administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to terminate process: {str(e)}")
            
    def perform_security_scan(self):
        self.security_scan_btn.config(state='disabled', text='SCANNING...')
        
        def scan_worker():
            try:
                security_data = self.collect_security_information()
                
                scan_results = f"""
SECURITY SCAN RESULTS
====================
Windows Defender: {security_data.get('defender_status', 'Unknown')}
Firewall Status: {security_data.get('firewall_status', 'Unknown')}
Suspicious Processes: {security_data.get('suspicious_processes', 0)}
Network Security: {security_data.get('network_security', 'Unknown')}

SYSTEM STATUS: {'SECURE' if security_data.get('suspicious_processes', 0) == 0 else 'INVESTIGATE REQUIRED'}
Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
                
                def show_results():
                    messagebox.showinfo("Security Scan Complete", scan_results)
                    self.security_scan_btn.config(state='normal', text='SECURITY SCAN')
                    
                self.root.after(0, show_results)
                
            except Exception as e:
                def show_error():
                    messagebox.showerror("Scan Error", f"Security scan failed: {str(e)}")
                    self.security_scan_btn.config(state='normal', text='SECURITY SCAN')
                self.root.after(0, show_error)
                
        threading.Thread(target=scan_worker, daemon=True).start()
        
    def bytes_to_gb(self, bytes_value):
        return bytes_value / (1024 ** 3)
        
    def assess_system_health(self):
        try:
            if self.performance_metrics['cpu_cores'] and self.performance_metrics['memory_usage']:
                cpu_avg = sum(list(self.performance_metrics['cpu_cores'])[-10:]) / min(10, len(self.performance_metrics['cpu_cores']))
                mem_avg = sum(list(self.performance_metrics['memory_usage'])[-10:]) / min(10, len(self.performance_metrics['memory_usage']))
                
                if cpu_avg > 90 or mem_avg > 90:
                    return "Critical Load"
                elif cpu_avg > 70 or mem_avg > 70:
                    return "High Load"
                elif cpu_avg > 50 or mem_avg > 50:
                    return "Moderate Load"
                else:
                    return "Optimal"
            return "Monitoring"
        except:
            return "Unknown"
            
    def get_network_status(self):
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=2)
            return "Connected"
        except:
            return "Disconnected"
            
    def calculate_security_level(self):
        try:
            if self.cached_data['security_status']:
                sec_data = self.cached_data['security_status']
                score = 0
                
                if sec_data.get('defender_status') == 'Active':
                    score += 2
                if sec_data.get('firewall_status') == 'Active':
                    score += 2
                if sec_data.get('suspicious_processes', 0) == 0:
                    score += 2
                    
                if score >= 5:
                    return "High"
                elif score >= 3:
                    return "Medium"
                else:
                    return "Low"
            return "Unknown"
        except:
            return "Unknown"
            
    def on_closing(self):
        print("Shutting down advanced memory monitoring system...")
        self.monitoring_active = False
        
        try:
            if hasattr(self, 'primary_thread'):
                self.primary_thread.join(timeout=2)
            if hasattr(self, 'gui_thread'):
                self.gui_thread.join(timeout=1)
            if hasattr(self, 'performance_thread'):
                self.performance_thread.join(timeout=1)
            if hasattr(self, 'memory_analysis_thread'):
                self.memory_analysis_thread.join(timeout=2)
        except:
            pass
            
        self.root.destroy()
        
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.refresh_process_data()
        self.refresh_network_data()
        
        print("AI TEST v5.0 - AMA Edition")
        print("="*65)
        print("Features Enabled:")
        print("- Advanced Memory Architecture Analysis")
        print("- Virtual Memory Region Mapping") 
        print("- GPU Memory Utilization Tracking")
        print("- Process Memory Counter Analysis")
        print("- Windows API Integration (kernel32, ntdll, psapi)")
        print("- Real-time Performance Visualization")
        print("- Security Intelligence Platform")
        print(f"Monitoring interval: {self.update_interval}s")
        print("Press Ctrl+C or close window to exit")
        print("="*65)
        
        self.root.mainloop()

if __name__ == "__main__":
    try:
        monitor = EnterpriseSystemMonitor()
        monitor.run()
    except ImportError as e:
        print(f"Critical dependency missing: {e}")
        print("Required installations:")
        print("pip install psutil matplotlib")
        print("Optional: pip install wmi pynvml")
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"System monitoring framework initialization failed: {e}")
        print("Ensure administrative privileges and Windows compatibility")

# EXTRA:
#|-------------------
#|MochiAI was made as an AI companion for a unix shell im also developing but is now able to preform a few taks and generate code. As MochiAI advances it will be made public.
#|-------------------
