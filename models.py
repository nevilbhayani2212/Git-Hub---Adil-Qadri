
import datetime
import enum
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, MetaData, create_engine
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship



# SQLALCHEMY_URL_DATABASE = "sqlite:///db.sqlite"
SQLALCHEMY_URL_DATABASE = "sqlite:///./db.sqlite"

engine = create_engine(SQLALCHEMY_URL_DATABASE)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
metadata = MetaData()
Base = declarative_base(metadata=metadata)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Register(Base):
    __tablename__ = 'register'
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String, index=True)
    password = Column(String, index=True)
    is_admin = Column(Boolean, default=False)
    otp = Column(String)


class Address(Base):
    __tablename__ = 'addresses'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('register.id'))
    full_name = Column(String)
    mobile_number = Column(String)
    house_no = Column(String)
    area = Column(String)
    city = Column(String)
    pincode = Column(String)
    state = Column(String)
    country = Column(String)

    user = relationship("Register", backref="addresses")


class Products(Base):
    __tablename__ = 'products'
    id = Column(Integer, primary_key=True, index=True)
    product_name = Column(String, index=True)
    product_details = Column(String, index=True)
    product_price = Column(String, nullable=True)
    product_old_price = Column(String, nullable=True)
    image = Column(String, index=True)
    category_id = Column(Integer, ForeignKey('categories.id'), index=True)
    discount_percentage = Column(String, index=True)
    availability = Column(Boolean, default=True)  
    fragrance = Column(String, nullable=True)
    gender = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    sales_count = Column(Integer, default=0)
    total_quantity = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow) 

    category = relationship("Category", backref="products")


class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class Videos(Base):
    __tablename__ = 'videos'
    id = Column(Integer, primary_key=True, index=True)
    upload_video = Column(String, index=True)
    image = Column(String, index=True)
    product_name = Column(String, index=True)
    price = Column(String, index=True)
    old_price = Column(String, index=True)
    description = Column(String, index=True)


class CartItem(Base):
    __tablename__ = 'cart_items'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('register.id'), index=True)
    product_id = Column(Integer, ForeignKey('products.id'), index=True)
    name = Column(String)
    category_id = Column(Integer)
    price = Column(Float)
    old_price = Column(Float)
    quantity = Column(Integer)
    image = Column(String)

    user = relationship("Register", backref="cart_items")
    product = relationship("Products")
    

class Offer(Base):
    __tablename__ = "offers"
    id = Column(Integer, primary_key=True, index=True)
    coupon_code = Column(String, unique=True, nullable=False)
    discount = Column(Float, nullable=False)
    min_products = Column(Integer, nullable=False)



class Reviews(Base):
    __tablename__ = 'reviews'
    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, ForeignKey('products.id'), index=True)  
    user_id = Column(Integer, ForeignKey('register.id'), index=True)  
    five_star = Column(Integer, default=5, index=True)
    note = Column(String, nullable=True)  
    photos_videos = Column(String, nullable=True, )
    title = Column(String, index=True,nullable=True)  
    review_date = Column(DateTime, default=datetime.datetime.utcnow)
    
    product = relationship("Products", backref="reviews")
    user = relationship("Register", backref="reviews")  



class StoreAddress(Base):
    __tablename__='store_addresses'
    id = Column(Integer, primary_key=True, index=True)
    store_name = Column(String, index=True)
    store_address = Column(String, index=True)
    state = Column(String, index=True)
    city = Column(String, index=True)
    pincode = Column(String, index=True)
    store_maps = Column(String, index= True)


class ContactUs(Base):
    __tablename__ = 'contact_us'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, index=True)
    mobile_number = Column(String, index=True)
    massage = Column(String, index=True)

    


class OrderStatus(enum.Enum):
    PENDING = "pending"
    PAID = "paid"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"


class Order(Base):
    __tablename__ = 'orders'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('register.id'), index=True)
    address_id = Column(Integer, ForeignKey('addresses.id'), index=True)
    total_amount = Column(Float)
    status = Column(String, default=OrderStatus.PENDING.value)
    payment_id = Column(String, nullable=True)
    razorpay_order_id = Column(String, nullable=True)
    razorpay_signature = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    user = relationship("Register", backref="orders")
    address = relationship("Address")
    items = relationship("OrderItem", back_populates="order")


class OrderItem(Base):
    __tablename__ = 'order_items'
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey('orders.id'), index=True)
    product_id = Column(Integer, ForeignKey('products.id'), index=True)
    name = Column(String)
    price = Column(Float)
    old_price = Column(Float)
    quantity = Column(Integer)
    image = Column(String)
    
    order = relationship("Order", back_populates="items")
    product = relationship("Products")


class Slider(Base):
    __tablename__ = 'slider'

    id = Column(Integer, primary_key=True, index=True)
    image = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


Base.metadata.create_all(bind=engine)
