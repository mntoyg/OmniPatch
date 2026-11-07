def lookup_username(connection, username):
    """Look up a username with intentionally unsafe SQL interpolation."""
    cursor = connection.cursor()
    query = f"SELECT username FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
