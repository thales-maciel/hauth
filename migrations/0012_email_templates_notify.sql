-- Migration 0012: NOTIFY trigger for auth.email_templates cache invalidation.
-- Any INSERT/UPDATE/DELETE on auth.email_templates publishes on the channel
-- "email_templates_updated" so live processes can refresh their cache.

CREATE OR REPLACE FUNCTION auth.notify_email_templates_updated() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('email_templates_updated', COALESCE(NEW.name, OLD.name));
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER email_templates_notify
    AFTER INSERT OR UPDATE OR DELETE ON auth.email_templates
    FOR EACH ROW EXECUTE FUNCTION auth.notify_email_templates_updated();
