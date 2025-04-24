@app.route("/search")
def search():
    query = request.args.get("query", "").lower()
    if not query:
        return render_template("search.html", results=None)
    
    # 예시: 상품 목록이 리스트로 존재한다고 가정
    # 실제로는 DB에서 필터링해야 함
    sample_products = [
        {"id": 1, "title": "아이폰 12", "price": "500000"},
        {"id": 2, "title": "갤럭시 버즈", "price": "80000"},
        {"id": 3, "title": "맥북 프로", "price": "1500000"},
    ]
    
    results = [p for p in sample_products if query in p["title"].lower()]
    
    return render_template("search.html", results=results)

@app.route("/send", methods=["GET", "POST"])
def send_money():
    if request.method == "POST":
        receiver_id = request.form["receiver_id"]
        amount = request.form["amount"]
        
        # 여기서 실제 송금 로직 처리: DB 업데이트 등
        # 지금은 예시로 출력만 해볼게
        print(f"사용자에게 송금: 받는 사람 = {receiver_id}, 금액 = {amount}")

        flash("송금이 완료되었습니다!")  # 위에 flash 메시지 표시됨
        return redirect(url_for("dashboard"))

    return render_template("send_money.html")
@app.route("/admin")
def admin():
    if not session.get("is_admin"):
        flash("관리자만 접근 가능합니다.")
        return redirect(url_for("dashboard"))
    return render_template("admin.html")
