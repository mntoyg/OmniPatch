def lookup_username(connection, username):
    """Look up a username using SQLite parameter binding."""
    cursor = connection.cursor()
    query = "SELECT username FROM accounts WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()
