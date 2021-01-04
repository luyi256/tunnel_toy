# Python程序设计#8作业

截止时间：2020年12月14日23:59:59

## 作业题目

使用venv创建开发环境

使用命令冻结依赖关系生成 requirements.txt

测试使用requirements.txt 重新部署在其他环境位置

将以上内容写成报告写在Markdown文档中提交作业

## 报告内容

本次作业不涉及代码，格式不做要求。

由于只提交一个文件，插入图片提交后在老师处无法显示，仅将控制台界面的所有显示内容复制到本报告中。

1. 使用venv创建开发环境

   ```shell
   # 在E盘test文件夹下创建名为test的环境
   E:\python> python -m venv E:\test 
   # 进入E:test\Scripts目录下，执行activate.bat，将进入test环境
   E:\test\Scripts>activate.bat
   (test) E:\test\Scripts>pip install websocket
   Collecting websocket
   # 其后的下载显示省略
   # 输入python进入解释器
   (test) E:\test\Scripts>python
   Python 3.7.3 (default, Apr 24 2019, 15:29:51) [MSC v.1915 64 bit (AMD64)] :: Anaconda, Inc. on win32
   
   Warning:
   This Python interpreter is in a conda environment, but the environment has
   not been activated.  Libraries may fail to load.  To activate this environment
   please see https://conda.io/activation
   
   Type "help", "copyright", "credits" or "license" for more information.
   >>> exit()   
   # deactivate退出环境
   (test) E:\test\Scripts>deactivate
   E:\test\Scripts>  
   ```

2. 使用命令冻结依赖关系生成 requirements.txt

   ```shell
   (test) E:\test\Scripts>pip freeze > requirements.txt
   ```

   得到requirements.txt的内容如下：

   ```
   cffi==1.14.4
   gevent==20.9.0
   greenlet==0.4.17
   pycparser==2.20
   websocket==0.2.1
   zope.event==4.5.0
   zope.interface==5.2.0
   ```

3. 测试使用requirements.txt 重新部署在其他环境位置
   首先创建新环境new_test

   ```shell
   E:\python> python -m venv E:\new_test
   # 进入E:\new_test环境，命令略
   E:\new_test>Scripts\activate.bat 
   ```

   接着将第2步中得到的requirements.txt复制到E:\new_test下，再将其部署在新的环境下：

   ```shell
   (new_test) E:\new_test>pip install -r requirements.txt
   Collecting cffi==1.14.4 (from -r requirements.txt (line 1))
     Using cached https://files.pythonhosted.org/packages/65/7b/cf83e7da59967d7f8599ac27338d570af4d770791b1ea744677b27aafcb4/cffi-1.14.4-cp37-cp37m-win_amd64.whl
   Collecting gevent==20.9.0 (from -r requirements.txt (line 2))
     Using cached https://files.pythonhosted.org/packages/e8/78/3852afe86b6406e5a6bdc3bc0cf35fe282eae496ce59b9cf8706f896fc22/gevent-20.9.0-cp37-cp37m-win_amd64.whl
   Collecting greenlet==0.4.17 (from -r requirements.txt (line 3))
     Using cached https://files.pythonhosted.org/packages/e4/ca/b15607286f4c2592200eb45b4779f22d4673d7575d2b285da00b86fac99c/greenlet-0.4.17-cp37-cp37m-win_amd64.whl
   Collecting pycparser==2.20 (from -r requirements.txt (line 4))
     Using cached https://files.pythonhosted.org/packages/ae/e7/d9c3a176ca4b02024debf82342dab36efadfc5776f9c8db077e8f6e71821/pycparser-2.20-py2.py3-none-any.whl
   Collecting websocket==0.2.1 (from -r requirements.txt (line 5))
     Using cached https://files.pythonhosted.org/packages/f2/6d/a60d620ea575c885510c574909d2e3ed62129b121fa2df00ca1c81024c87/websocket-0.2.1.tar.gz
   Collecting zope.event==4.5.0 (from -r requirements.txt (line 6))
     Using cached https://files.pythonhosted.org/packages/9e/85/b45408c64f3b888976f1d5b37eed8d746b8d5729a66a49ec846fda27d371/zope.event-4.5.0-py2.py3-none-any.whl
   Collecting zope.interface==5.2.0 (from -r requirements.txt (line 7))
     Using cached https://files.pythonhosted.org/packages/e6/a1/15072b271df268d142cd4377f750836e3e76dfcf9de16107132c84b2f370/zope.interface-5.2.0-cp37-cp37m-win_amd64.whl
   Requirement already satisfied: setuptools in e:\new_test\lib\site-packages (from gevent==20.9.0->-r requirements.txt (line 2)) (40.8.0)
   Installing collected packages: pycparser, cffi, zope.interface, greenlet, zope.event, gevent, websocket
     Running setup.py install for websocket ... done
   Successfully installed cffi-1.14.4 gevent-20.9.0 greenlet-0.4.17 pycparser-2.20 websocket-0.2.1 zope.event-4.5.0 zope.interface-5.2.0
   # 退出环境
   (new_test) E:\new_test>deactivate
   E:\new_test> 
   ```

   