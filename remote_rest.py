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
      log_text=f'finish insert into table: name: {name}, password: {password}, rate: {rate}'
      logger.info(log_text)
      return response.text(log_text)

@app.put('/updaterate/<name>/<rate>')
async def update_rate(req,name,rate):
  async with aiosqlite3.connect(app.config.DB_NAME) as db:
    async with db.execute("update user set rate=? where username=?", (rate, name)):
      await db.commit()
      log_text=f'finish update table: name: {name}, rate: {rate}'
      logger.info(log_text)
      return response.text(log_text)

@app.put('/updatepwd/<name>/<password>')
async def update_pwd(req,name,password):
  async with aiosqlite3.connect(app.config.DB_NAME) as db:
    async with db.execute("update user set password=? where username=?", (password, name)):
      await db.commit()
      log_text=f'finish update table: name: {name}, password: {password}'
      logger.info(log_text)
      return response.text(log_text)

@app.delete('/delete/<name>')
async def delete_one(req,name):
  async with aiosqlite3.connect(app.config.DB_NAME) as db:
    async with db.execute("delete from user where username=?", (name,)):
      await db.commit()
      log_text=f'finish delete from table: name: {name}'
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

