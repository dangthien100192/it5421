def find(conn, name):
    return conn.execute("SELECT name FROM customers WHERE name = '" + name + "'").fetchall()
