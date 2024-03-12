#include <chrono>
#include <mutex>
#include <pqxx/pqxx>
#include <stack>

#include "bytes.hpp"

namespace pns {

using namespace std::literals;

class PGConnPool;

// smart-pointer-like wrapper around a pqxx::connection; when this wrapper is destructed the
// connection is automatically returned to the PGConnPool.  This wrapper *must not* outlive the
// PGConnPool that created it.
class PGConn {
    PGConnPool& pool_;
    std::unique_ptr<pqxx::connection> conn_;

    friend class PGConnPool;

    PGConn(PGConnPool& pool, std::unique_ptr<pqxx::connection> conn) :
            pool_{pool}, conn_{std::move(conn)} {}

  public:
    // Closes/destroys the underlying connection, which also means that this connection will not be
    // readded to the pool on destruction of the PGConn wrapper.
    void close() { conn_.reset(); }

    // Destructor; returns this connection to the pool (unless `close()` has been called).
    ~PGConn();

    pqxx::connection& operator*() const noexcept { return conn_.operator*(); }
    pqxx::connection* operator->() const noexcept { return conn_.operator->(); }

    operator pqxx::connection&() const noexcept { return **this; }
};

class PGConnPool {
    using steady_clock = std::chrono::steady_clock;
    using steady_time = steady_clock::time_point;
    std::string pg_connect_;
    // queue of connections + time added to the idle queue
    std::deque<std::pair<std::unique_ptr<pqxx::connection>, steady_time>> idle_conns_;
    std::mutex mutex_;
    int count_ = 0;

  public:
    /// After how long of being unused before we kill off idle connections.  (This isn't an active
    /// timer: connections get killed off only when retrieving or releasing a connection).  0 or
    /// negative mean there is no idle timeout.  After changing this you may want to call
    /// `clear_idle_conns()` to apply the new setting to currently idle connections.
    std::chrono::milliseconds max_idle_time = 10min;

    /// Maximum number of idle connections we will keep alive.  If 0 then we never keep any idle
    /// connections at all and each call to `get()` will have to reconnect.
    ///
    /// If negative then there is no limit (aside from max_idle_time) on the number of idle
    /// connections that will be kept around.
    ///
    /// After changing this you may want to call `clear_idle_conns()` to apply the new setting.
    int max_idle = -1;

    /// Create the connection pool and establish the first connection(s), throwing if we are unable
    /// to connect.  We always establish at least one connection to test the connection; if
    /// initial_conns is 0 then we close it rather than returning it to the initial pool.
    PGConnPool(std::string pg_connect, int initial_conns = 1);

    /// Gets a connection; if none are available a new connection is constructed.  This tests the
    /// status of the connection before returning it, discarding any connections that are no longer
    /// open (e.g. because of error or server timeout).
    ///
    /// We always return the most-recently-used connection (so that excess connections have a chance
    /// to reach the max idle time).
    ///
    /// Calling this function also triggers a check for excess idle connections after selecting a
    /// connection from the pool.
    ///
    /// Returns a PGConn wrapper which is smart-pointer-like and automatically returns the
    /// connection to the pool upon destruction.  You *must ensure* that the returned value does not
    /// outlive the creating PGConnPool.
    PGConn get();

    /// Releases a connection back into the pool for future use.  This is not called directly, but
    /// instead implicit during destruction of the PGConn wrapper.
    void release(std::unique_ptr<pqxx::connection> conn);

    /// Clears any connections that have been idle longer than `max_idle`.  This is called
    /// automatically whenever `release` or `get` are called, but can be called externally (e.g. on
    /// a timer) if more strict idle time management is desired.
    void clear_idle_conns();

  protected:
    std::unique_ptr<pqxx::connection> pop_conn();

    std::unique_ptr<pqxx::connection> make_conn();
};

// Helper for extracting namespaces from a pg array
struct Int16ArrayLoader {
    std::vector<int16_t> a;
};

}  // namespace pns

namespace pqxx {

template <>
inline const std::string type_name<pns::AccountID>{"pns::AccountID"};
template <>
inline const std::string type_name<pns::Ed25519PK>{"pns::Ed25519PK"};
template <>
inline const std::string type_name<pns::SubaccountTag>{"pns::SubaccountTag"};
template <>
inline const std::string type_name<pns::Signature>{"pns::Signature"};
template <>
inline const std::string type_name<pns::EncKey>{"pns::EncKey"};

template <typename T, typename = std::enable_if_t<pns::is_bytes<T>>>
struct pns_byte_helper {
    static constexpr size_t SIZE = T::SIZE;
    static T from_string(std::string_view text) {
        const auto size = internal::size_unesc_bin(text.size());
        if (size != SIZE)
            throw conversion_error{
                    "Invalid byte length (" + std::to_string(size) + ") for pns::bytes<" +
                    std::to_string(SIZE) + ">-derived object\n"
#ifndef NDEBUG
                    + std::string{text}
#endif
            };
        T val;
        internal::unesc_bin(text, val.data());
        return val;
    }

    using BSV_traits = string_traits<std::basic_string_view<std::byte>>;

    static zview to_buf(char* begin, char* end, const T& val) {
        return BSV_traits::to_buf(begin, end, {val.data(), val.size()});
    }
    static char* into_buf(char* begin, char* end, const T& val) {
        return BSV_traits::into_buf(begin, end, {val.data(), val.size()});
    }
    static std::size_t size_buffer(const T&) noexcept {
        return internal::size_esc_bin(SIZE);
    }
};

template <typename T>
struct nullness<T, std::enable_if_t<pns::is_bytes<T>>> : pqxx::no_null<T> {};

template <>
struct string_traits<pns::AccountID> : pns_byte_helper<pns::AccountID> {};
template <>
struct string_traits<pns::Ed25519PK> : pns_byte_helper<pns::Ed25519PK> {};
template <>
struct string_traits<pns::SubaccountTag> : pns_byte_helper<pns::SubaccountTag> {};
template <>
struct string_traits<pns::Signature> : pns_byte_helper<pns::Signature> {};
template <>
struct string_traits<pns::EncKey> : pns_byte_helper<pns::EncKey> {};

template <>
struct string_traits<pns::Int16ArrayLoader> {
    static pns::Int16ArrayLoader from_string(std::string_view in);
};

template <>
struct nullness<pns::Int16ArrayLoader> : pqxx::no_null<pns::Int16ArrayLoader> {};

}  // namespace pqxx
