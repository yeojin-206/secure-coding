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
