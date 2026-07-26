from sqlalchemy.orm import Session
from app.models.user import User


def create_user(db: Session, name: str, email: str, password: str):
    user = User(
        name=name,
        email=email,
        password=password
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def get_users(db: Session):
    return db.query(User).all()


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def update_user(db: Session, user_id: int, name: str, password: str):
    user = get_user(db, user_id)

    if user:
        user.name = name
        user.password = password

        db.commit()
        db.refresh(user)

    return user


def delete_user(db: Session, user_id: int):
    user = get_user(db, user_id)

    if user:
        db.delete(user)
        db.commit()

    return user