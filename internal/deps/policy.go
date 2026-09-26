package deps

// MinPolicy lists a few modules we care about for the course.
// (Adjust versions as you like; this is illustrative.)
var MinPolicy = map[string]string{
	"modernc.org/sqlite":           "1.29.0",
	"github.com/golang-jwt/jwt/v5": "5.2.0",
	"golang.org/x/crypto":          "0.23.0",
}
