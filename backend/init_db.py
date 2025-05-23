from database import Base, engine, SessionLocal
from models import User
import bcrypt

def init():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        hashed_pw = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        new_admin = User(username="admin", hashed_password=hashed_pw, role="admin")
        db.add(new_admin)
        db.commit()
    db.close()

if __name__ == "__main__":
    init()