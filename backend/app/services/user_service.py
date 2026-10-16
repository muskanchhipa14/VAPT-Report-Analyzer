from sqlalchemy.orm import Session
from app.models.user import User


from app.core.roles import normalize_role


def create_user(db: Session, name: str, email: str, password: str, role: str = "user"):
    normalized_role = normalize_role(role)
    user = User(
        name=name,
        email=email,
        password=password,
        role=normalized_role
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


def update_user(db: Session, user_id: int, name: str = None, password: str = None, role: str = None):
    user = get_user(db, user_id)

    if user:
        if name is not None:
            user.name = name
        if password is not None:
            user.password = password
        if role is not None:
            user.role = normalize_role(role)

        db.commit()
        db.refresh(user)

    return user


def delete_user(db: Session, user_id: int):
    user = get_user(db, user_id)

    if user:
        db.delete(user)
        db.commit()

    return user


def seed_cdac_users(db: Session):
    """
    Seeds default C-DAC organization accounts if they don't already exist:
    1. C-DAC Security Officer (Full clearance & confidential source code access)
    2. Security Analyst (Audit & scanning clearance)
    3. Standard User (General reports & KB clearance; confidential source code access restricted)
    Also ensures existing admin accounts have C-DAC officer clearance.
    """
    cdac_defaults = [
        {
            "name": "C-DAC Security Officer",
            "email": "officer@cdac.in",
            "password": "cdac@123",
            "role": "cdac_officer"
        },
        {
            "name": "Security Auditor",
            "email": "analyst@cdac.in",
            "password": "analyst@123",
            "role": "security_analyst"
        },
        {
            "name": "Standard User",
            "email": "user@cdac.in",
            "password": "user@123",
            "role": "user"
        }
    ]

    for item in cdac_defaults:
        existing = get_user_by_email(db, item["email"])
        if not existing:
            create_user(
                db=db,
                name=item["name"],
                email=item["email"],
                password=item["password"],
                role=item["role"]
            )
        elif existing.role != item["role"]:
            existing.role = item["role"]
            db.commit()

    # Upgrade muskan@gmail.com to cdac_officer if present
    admin_user = get_user_by_email(db, "muskan@gmail.com")
    if admin_user and admin_user.role != "cdac_officer":
        admin_user.role = "cdac_officer"
        db.commit()