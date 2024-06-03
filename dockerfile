FROM python:3.12

WORKDIR /usr

COPY requirements.txt /usr/requirements.txt

RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY ./app /usr/app

WORKDIR /usr/app

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]