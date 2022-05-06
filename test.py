#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@Version: 1.0.2
@Project: Secure-Multi-Party-Computation-Protocol
@Author: Zhan Shi
@Time  : 2022/5/4 17:42
@File: test.py
@License: MIT
"""
import json
import os
import sys
import time
import unittest
from multiprocessing import Pool, cpu_count

import pandas as pd
import tqdm

sys.path.append("test_case/")  # 添加测试文件路径
from BeautifulReport import BeautifulReport

TEMPLATE_PATH = 'test_case/template/template'  # 模板文件路径
REPORT_PATH = 'test_case/report'  # 报告文件路径
REPORT_FILE = 'HTMLReport.html'  # 报告文件
DESCRIPTION = '安全多方计算协议测试'  # 报告名称


def format_report(_report):
    """
    规范报告格式
    :param _report: 测试报告数据
    :return: 规范后的测试报告数据
    """
    _output = {'testPass': 0, 'testResult': [], 'testFail': 0, 'testSkip': 0, 'testError': 0}

    for v in _report:
        _output['testPass'] += v.get()['testPass']
        for m in v.get()['testResult']:
            _output.get('testResult').append(m)
        _output['testAll'] = len(v.get()['testResult'])
        _output['testName'] = v.get()['testName']
        _output['testFail'] += v.get()['testFail']
        _output['beginTime'] = v.get()['beginTime']
        _output['totalTime'] = v.get()['totalTime']
        _output['testError'] += v.get()['testError']
        _output['testSkip'] += v.get()['testSkip']

    return _output


def output_report(_report):
    """
    输出测试报告
    :param _report: 测试报告数据
    """
    pd.DataFrame(_report).to_csv("{0}/CSVReport.csv".format(REPORT_PATH), header=False, index=False)

    template_path = TEMPLATE_PATH
    override_path = os.path.abspath(REPORT_PATH) \
        if os.path.abspath(REPORT_PATH).endswith('/') \
        else os.path.abspath(REPORT_PATH) + '/'

    with open(template_path, 'rb') as file:
        body = file.readlines()
    with open(override_path + REPORT_FILE, 'wb') as write_file:
        for item in body:
            if item.strip().startswith(b'var resultData'):
                head = '    var resultData = '
                item = item.decode().split(head)
                item[1] = head + json.dumps(
                    _report, ensure_ascii=False, indent=4)
                item = ''.join(item).encode()
                item = bytes(item) + b';\n'
            write_file.write(item)


def run():
    """
    开始测试
    :return: 测试报告数据
    """
    # 构造测试用例
    cases = unittest.defaultTestLoader.discover("test_case", pattern="test_smpcp.py", top_level_dir=None)
    # 读取测试用例 运行测试
    return BeautifulReport(cases).report(filename=REPORT_FILE, log_path=REPORT_PATH, description=DESCRIPTION)


if __name__ == '__main__':
    start = time.time()  # 开始时间
    times = 100  # TODO 测试次数
    process_pool = Pool(cpu_count())  # 开启进程池
    # 进度条
    process_bar = tqdm.tqdm(iterable=range(times), ncols=80, nrows=20, desc=DESCRIPTION)
    # 多进程测试
    report = [process_pool.apply_async(run, (), callback=lambda _: process_bar.update()) for _ in range(times)]
    # 进程开始
    process_pool.close()
    process_pool.join()
    # 测试报告
    output = format_report(report)
    output_report(output)
