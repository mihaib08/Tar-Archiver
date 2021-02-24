#!/usr/bin/python3 -u
# Copyright 2019 Darius Neatu (neatudarius@gmail.com)

import os
import pathlib
import subprocess

from .parser import get_config
from .utils import *


def update_grade(config, points):
    assert config is not None

    config.grade += points
    if points < 0:
        log('{} points penalty applied!\n'.format(points))


def check_deps(config):
    assert config is not None

    log('+++++ check_deps ...')
    deps = config.deps

    child = subprocess.run(['uname', '-a', ], shell=False,
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL,
                           )
    assert child.returncode == 0, child.stderr
    log('{:20s} - Linux'.format('system'))
    log('\t config: {}'.format(extract_stdout(child).split('\n')[0]))

    for dep in deps:
        child = subprocess.run(['which', dep, ], shell=False,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               )
        if child.returncode != 0:
            log('{} needs to be installed!'.format(dep))
            return child.returncode
        log('{:20s} - installed'.format(dep))

        child = subprocess.run([dep, '--version', ], shell=False,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               )
        if child.returncode != 0:
            log(extract_stderr(child))
            return child.returncode
        log('\tversion: {}'.format(extract_stdout(child).split('\n')[0]))

    log('----- check_deps\n')
    return 0


def make_build(config):
    assert config is not None

    log('+++++ make_build ...')
    makefile = 'Makefile'
    if not pathlib.Path(makefile).is_file():
        log('{} is missing!'.format(makefile))
        return -1

    try:
        child = subprocess.run(['make', 'build', ], shell=False,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               )
    except Exception as e:
        log('----- make_build - UPS: {}'.format(str(e)))
        unindent_log()
        return -1

    if child.returncode != 0:
        log('Compile ERRORS found. STOP. Please fix them.')
        log('{}'.format(extract_stderr(child)))
        return child.returncode

    if config.penalty_warnings > 0:
        warnings = child.stderr.decode("utf-8")
        if len(warnings) > 0:
            log('WARNINGS found. Please fix them.')
            update_grade(config, -config.penalty_warnings)
            log('{}'.format(warnings))

    for task in config.tasks:
        if not pathlib.Path(task.id).is_file() or not os.access(os.path.join('.', task.id), os.X_OK):
            log('[WARNING] Executable \'{}\' not found!'.format(task.id))

    log('----- make_build')
    return 0


def make_clean(config):
    assert config is not None

    log('+++++ make_clean ...')

    try:
        child = subprocess.run(['make', 'clean', ], shell=False,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               )
    except Exception as e:
        log('----- make_clean - UPS: {}'.format(str(e)))
        unindent_log()
        return -1

    if child.returncode != 0:
        log('\'make clean\' failed. Fix it!')
        update_grade(config, -config.grade)

        log('{}'.format(extract_stdout(child)))
        return child.returncode

    log('----- make_clean')
    return 0


def check_readme(config):
    if config.penalty_readme <= 0:
        return 0  # check not enable

    log('+++++ running check_readme ...')

    readme = pathlib.Path('README')
    if not readme.is_file():
        log('\'{}\' is missing!'.format(readme.name))
        update_grade(config, -config.penalty_readme)
    elif readme.stat().st_size == 0:
        log('Empty \'{}\'!'.format(readme.name))
        update_grade(config, -config.penalty_readme)
    elif readme.stat().st_size < 64:
        log('\'{}\' too short! Nice try! :p'.format(readme.name))
        update_grade(config, -config.penalty_readme)

    log('----- running check_readme\n')
    return 0


def check_style(config):
    if config.coding_style <= 0:
        return 0  # check not enable

    log('+++++ running check_style ({:g}p)...'.format(config.coding_style))

    cmd = './check_utils/external/cpp/cpplint.py $(find . -name "*.c" -or -name "*.h")'

    try:
        child = subprocess.run(cmd, shell=True,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE,
                               )
    except Exception as e:
        log('----- running check_style - UPS: {}'.format(str(e)))
        unindent_log()
        return -1

    if child.returncode != 0:
        coding_style_grade = 0
    else:
        coding_style_grade = (1.0 * max(config.grade, 0) /
                              config.tests_points) * config.coding_style
    config.grade += coding_style_grade

    log('{}\n'.format(extract_stderr(child)))

    # log('Note: The coding style points are uniformly distributed per task.')
    log('----- running check_style - grade {:g}/{:g}\n'.format(
        coding_style_grade, config.coding_style))

    return 0


def run_test(task, test, use_valgrind=False, ):
    indent_log()
    stage_name = 'test' if not use_valgrind else 'valgrind'
    log('running {:10s} ...'.format(stage_name))

    cmd = None
    if not use_valgrind:
        # man timeout: 124 if command times out
        expected_error_code = 124

        cmd = './{}'.format(task.id)
    else:
        # choose an error to be returned by valgrind
        expected_error_code = 69

        cmd = 'valgrind '              \
            '--leak-check=full '       \
            '--show-reachable=no '     \
            '--show-leak-kinds=all '   \
            '--error-exitcode={} '     \
            '--log-file={} '           \
            './{}'.format(expected_error_code, test.log_valgrind, task.id)

    set_mem_bytes(task.memory)

    try:
        child = subprocess.run(cmd, shell=False if not task.use_valgrind else True,
                               stdin=open(
                                   test.input, 'r') if task.use_stdin else subprocess.DEVNULL,
                               stdout=open(
                                   test.output, 'w') if task.use_stdout else subprocess.DEVNULL,
                               stderr=subprocess.PIPE,
                               timeout=task.timeout if not task.use_valgrind else 500,
                               preexec_fn=limit_process_memory if task.memory and not task.use_valgrind else None,
                               )
    except subprocess.TimeoutExpired as e:
        log_replace('running {:10s} - TLE: {}'.format(stage_name, str(e)))
        unindent_log()
        return -1
    except Exception as e:
        log_replace('running {:10s} - UPS: {}'.format(stage_name, str(e)))
        unindent_log()
        return -1

    if child.returncode != 0:
        if not use_valgrind:
            log_replace(
                'running {:10s} - UPS: exit code = {}'.format(stage_name, child.returncode))
        elif child.returncode == expected_error_code:
            log_replace('running {:10s} - MEM_UPS'.format(stage_name))
        else:
            bug()

        unindent_log()
        return child.returncode

    log_replace('running {:10s} - OK'.format(stage_name))
    unindent_log()
    return 0


def check_test(grader, test):
    indent_log()
    stage_name = 'check'
    log('running {:10s} ...'.format(stage_name))
    cmd = '{} {} {} {} {}'.format(
        grader, test.input, test.output, test.ref, test.points)

    grade_file = '.check.grade'
    if pathlib.Path(grade_file).is_file():
        pathlib.Path(grade_file).unlink()

    try:
        child = subprocess.run(cmd, shell=True,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE,
                               )
    except Exception as e:
        log_replace('running {:10s} - UPS: {}'.format(stage_name, str(e)))
        unindent_log()
        return -1

    if child.returncode != 0:
        log_replace(
            'running {:10s} - WA: {}'.format(stage_name, extract_stderr(child)))
        unindent_log()
        return child.returncode

    assert pathlib.Path(grade_file).is_file(), grade_file
    test.grade = 0
    with open(grade_file, 'r') as f:
        test.grade = float(f.readlines()[0].rstrip())
    pathlib.Path(grade_file).unlink()

    warnings = extract_stderr(child)
    log_replace('running {:10s} - OK{}'.format(stage_name, (': {}'.format(warnings)
                                                            if len(warnings) > 0 else '')))
    unindent_log()
    return 0


def run_task(task):
    indent_log()
    log('+++++ running task {} ({:g}p) ...\n'.format(task.id, task.points))

    for test in task.tests:
        indent_log()
        log('+++++ running test {}'.format(test.id))

        stages = [
            lambda: run_test(task, test),
            lambda: check_test(task.grader,  test),
        ]
        if task.use_valgrind:
            stages.append(lambda: run_test(task, test, use_valgrind=True))

        code = 0
        for stage in stages:
            code, seconds = run_and_measure(stage)

            indent_log(2)
            log('stage time: {}'.format(seconds))
            unindent_log(2)

            if code != 0:
                break

        if code != 0:
            test.grade = 0

        task.grade += test.grade
        log('----- running test {} - grade {:g}/{:g}\n'.format(test.id,
                                                               test.grade, test.points))
        unindent_log()

    log('----- running task {} - grade {:g}/{:g}\n'.format(task.id,
                                                           task.grade, task.points))
    unindent_log()
    return 0


def run_tasks(config):
    log('+++++ running all tasks')

    for task in config.tasks:
        run_task(task)
        config.grade += task.grade

    log('----- running all tasks\n')
    return 0


def checker_run():
    config = get_config()
    assert config is not None

    checks = [
        lambda: check_deps(config),
        lambda: make_build(config),
        lambda: run_tasks(config) or config.grade == 0,
        lambda: check_style(config),
        lambda: check_readme(config),
        lambda: make_clean(config),
    ]

    for check in checks:
        ret = check()
        if ret != 0:
            break

    # don't give negative grades
    config.grade = config.grade if config.grade > 0 else 0

    log('\n\t\t\tFinal grade: {:g}'.format(config.grade))
