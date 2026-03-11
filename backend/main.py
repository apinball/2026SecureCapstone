from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello Capstone! 백엔드 서버가 정상 작동 중입니다. (현재: 레거시 통신)"}