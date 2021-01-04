# Python程序设计#7作业

截止时间：2020年12月7日23:59:59

## 作业题目

实现remoteProxy的用户数据库的REST管理接口

基于Sanic实现对user.db数据库（SQLite）的管理接口

支持对user用户的增、删、改、查操作。

初步掌握Sanic的使用方法。

## remoteRest代码

remoteRest代码嵌入下方的code block中。

```python
from sanic import Sanic
from sanic import response
from sanic.response import json
import aiosqlite3
import logging

app = Sanic(name="remote_rest")

db_settings = {
    'DB_HOST': 'localhost',
    'DB_NAME': 'user.db'
}
app.config.update(db_settings)

@app.get('/user/<name>')
async def get_one_user(req, name):
  user = list()
  db = await aiosqlite3.connect(app.config.DB_NAME)
  cursor = await db.execute("select password, rate from user where username=?", (name,))
  row = await cursor.fetchone()
  user = {'name': name, 'password': row[0], 'rate': row[1]}
  logger.info(f'get one user info:{user}')
  return response.json(user)

@app.get('/user')
async def get_user(req):
  userlist = list()
  async with aiosqlite3.connect(app.config.DB_NAME) as db:
    async with db.execute("select username, password, rate from user") as cursor:
      logger.info('get all user info:')
      row = await cursor.fetchone()
      while row:
        user = {'name': row[0], 'password': row[1], 'rate': row[2]}
        logger.info(f'{user}')
        userlist.append(user)
        row = await cursor.fetchone()
  return response.json(userlist)

@app.post('/add/<name>/<password>/<rate>')
async def add_user(req,name,password,rate):
  async with aiosqlite3.connect(app.config.DB_NAME) as db:
    async with db.execute("insert into user values(?,?,?)", (name, password, rate)):
      await db.commit()
      log_text=f'finish insert into table: name:{name}, password:{password}, rate:{rate}'
      logger.info(log_text)
      return response.text(log_text)

@app.put('/updaterate/<name>/<rate>')
async def update_rate(req,name,rate):
  async with aiosqlite3.connect(app.config.DB_NAME) as db:
    async with db.execute("update user set rate=? where username=?", (rate, name)):
      await db.commit()
      log_text=f'finish update table: name:{name}, rate:{rate}'
      logger.info(log_text)
      return response.text(log_text)

@app.put('/updatepwd/<name>/<password>')
async def update_pwd(req,name,password):
  async with aiosqlite3.connect(app.config.DB_NAME) as db:
    async with db.execute("update user set password=? where username=?", (password, name)):
      await db.commit()
      log_text=f'finish update table: name:{name}, password:{password}'
      logger.info(log_text)
      return response.text(log_text)

@app.delete('/delete/<name>')
async def delete_one(req,name):
  async with aiosqlite3.connect(app.config.DB_NAME) as db:
    async with db.execute("delete from user where username=?", (name,)):
      await db.commit()
      log_text=f'finish delete from table: name:{name}'
      logger.info(log_text)
      return response.text(log_text)

@app.delete('/deleteall')
async def delete_all(req):
  db = await aiosqlite3.connect(app.config.DB_NAME)
  await db.execute("delete from user")
  await db.commit()
  log_text='finish delete all tuples in table'
  logger.info(log_text)
  return response.text(log_text)

if __name__ == "__main__":
  # logging
  logger = logging.getLogger(__name__)
  logger.setLevel(level=logging.DEBUG)
  handler = logging.FileHandler('remote_rest.log')
  formatter = logging.Formatter('%(asctime)s %(levelname).1s %(lineno)-3d %(funcName)-20s %(message)s')
  handler.setFormatter(formatter)
  logger.addHandler(handler)
  app.run(host="0.0.0.0", port=8891)
```

## 代码说明

源代码中不要出现大段的说明注释，所有文字描述在本节中以行号引用说明。

#### 功能

本次作业使用sanic和REST API完成和数据库的交互，实现了如下功能：

- `get_one_user`获取一个用户的信息
- `get_user`获取所有用户的信息
- `add_user`添加用户
- `update_rate`更新用户的rate（上网速率）
- `update_pwd`更新用户的密码
- `delete_one`删除一个用户
- `delete_all`删除所有用户

#### 规范

实现的过程非常简单，从规范的角度，应该使功能和REST的API对应：

1. 使用GET查询
2. 使用POST添加
3. 使用PUT修改
4. 使用DELETE删除

#### 实现

实现的一个功能大致过程：

1. 确定REST的API，确定路由，例如`@app.put('/updatepwd/<name>/<password>')`使用put方法，路由是`/updatepwd/<name>/<password>`
2. 使用`async`定义函数，例如`async def update_pwd(req,name,password):`
3. 跟数据库建立连接，而后执行SQL语句，提交，记录日志，返回需要的结果给web

#### 验证

使用Insomnia可以很方便地验证：

![image-20201205154039080](E:\python\fig\image-20201205154039080.png)

也通过查看日志可以确定是否执行正确，以下日志验证了所有的功能：

```
2020-12-05 15:27:22,737 I 30  get_user             get all user info:
2020-12-05 15:27:22,738 I 34  get_user             {'name': 'iiii', 'password': 'jjjj', 'rate': 600000}
2020-12-05 15:27:43,887 I 45  add_user             finish insert into table: name:aaaa, password:bbbb, rate:600000
2020-12-05 15:28:01,866 I 22  get_one_user         get one user info:{'name': 'aaaa', 'password': 'bbbb', 'rate': 600000}
2020-12-05 15:30:44,537 I 54  update_rate          finish update table: name:iiii, rate:5000
2020-12-05 15:30:51,287 I 30  get_user             get all user info:
2020-12-05 15:30:51,288 I 34  get_user             {'name': 'iiii', 'password': 'jjjj', 'rate': 5000}
2020-12-05 15:30:51,289 I 34  get_user             {'name': 'aaaa', 'password': 'bbbb', 'rate': 600000}
2020-12-05 15:31:00,860 I 63  update_pwd           finish update table: name:iiii, password:kkkk
2020-12-05 15:31:05,726 I 30  get_user             get all user info:
2020-12-05 15:31:05,726 I 34  get_user             {'name': 'iiii', 'password': 'kkkk', 'rate': 5000}
2020-12-05 15:31:05,727 I 34  get_user             {'name': 'aaaa', 'password': 'bbbb', 'rate': 600000}
2020-12-05 15:31:10,282 I 72  delete_one           finish delete from table: name:aaaa
2020-12-05 15:31:13,308 I 30  get_user             get all user info:
2020-12-05 15:31:13,309 I 34  get_user             {'name': 'iiii', 'password': 'kkkk', 'rate': 5000}
2020-12-05 15:31:16,129 I 81  deleteall            finish delete all tuples in table
2020-12-05 15:31:19,055 I 30  get_user             get all user info:
```

