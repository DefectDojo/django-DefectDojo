class DbRouter:
    def db_for_read(self, model, **hints):
        """
        Directs all read operations to the 'replica' database.
        """
        return 'replica'

    def db_for_write(self, model, **hints):
        """
        Directs all write operations to the 'default' database.
        """
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allows relations if both objects belong to the same database.
        """
        return obj1._state.db == obj2._state.db

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Ensures that all migrations go to the 'default' database.
        """
        return db == 'default'