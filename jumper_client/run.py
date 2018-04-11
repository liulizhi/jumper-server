#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-4-11 下午4:48
# @Author  : QiRui.Su <schangech@gmail.com>
# @Site    :
# @File    : run.py
# @Software: PyCharm
# @Desc     :
# @license : Copyright(C), Rongcapital.Inc
# @Contact : QiRui.Su <schangech@gmail.com>

from pathlib import Path
import click

from .config import Config

__version = "v1.0.0"


@click.command()
@click.option('--conf', default="jumper.yaml", help='configure file.')
@click.option('--version', default=False, type=bool,
              help='print version.')
def main(conf, version):
    if version is True:
        print("Version: ", __version)

    if not Path(conf).exists():
        print("Not found configure file")
        import sys
        sys.exit(1)

    c = Config(conf)


if __name__ == "__main__":
    main()
