#!/usr/bin/env python3
import click
import subprocess

ufo_commander = click.Group()

@click.command()
def push():
    subprocess.run(['git', 'push', 'sourcehut'])
    subprocess.run(['git', 'push', 'github'])

ufo_commander.add_command(push)
ufo_commander()
