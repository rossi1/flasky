from app import app, db
from flask_script import Manager

manager = Manager(app)


@manager.command
def create_db():
    db.drop_all()
    db.create_all()


if __name__ == '__main__':
    manager.run()


