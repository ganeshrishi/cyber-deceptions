from flask import Flask, request, render_template_string
import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# ------------------ Honeypot ------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")
        ip = request.remote_addr
        time = datetime.datetime.now()

        with open("logs.txt", "a") as f:
            f.write(f"{ip},{user},{pwd},{time}\n")

        return "<h3>Login Failed</h3><a href='/'>Back</a>"

    return '''
    <h2>Secure Login</h2>
    <form method="post">
    <input name="username" placeholder="Username"><br><br>
    <input name="password" type="password"><br><br>
    <button>Login</button>
    </form>
    <br><a href="/dashboard">Go to Dashboard</a>
    '''

# ------------------ Dashboard ------------------
@app.route("/dashboard")
def dashboard():
    data = []

    try:
        with open("logs.txt", "r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) > 0:
                    data.append(parts[0])
    except:
        return "No logs found"

    if len(data) == 0:
        return "No data yet"

    df = pd.DataFrame(data, columns=["ip"])
    counts = df.value_counts().reset_index(name="attempts")

    # ML Model
    model = IsolationForest(contamination=0.2)
    model.fit(counts[["attempts"]])
    counts["anomaly"] = model.predict(counts[["attempts"]])

    # Convert to HTML
    table_html = counts.to_html(index=False)

    alerts = ""
    for i in range(len(counts)):
        if counts["anomaly"][i] == -1:
            alerts += f"<p style='color:red;'>⚠️ Suspicious IP: {counts['ip'][i]}</p>"

    return f"""
    <h1>Cyber Attack Dashboard</h1>
    {alerts}
    {table_html}
    <br><a href="/">Back to Login</a>
    """

# ------------------ Run ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)