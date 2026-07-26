from sqlalchemy.orm import Session
from app.models.user import User


def login(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()

    if not user:
        return None

    if user.password != password:
        return None

    return user


def change_password(
    db: Session,
    email: str,
    old_password: str,
    new_password: str
):
    user = db.query(User).filter(User.email == email).first()

    if not user:
        return None

    if user.password != old_password:
        return None

    user.password = new_password

    db.commit()
    db.refresh(user)

    return user