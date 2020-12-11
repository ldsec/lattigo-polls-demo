package main

import (
	"encoding/json"
	"fmt"
	"lattigo-polls-demo/utils"
	"log"
	"net/http"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/ldsec/lattigo/v2/bfv"
)

// Poll is the main data type representing an encrypted poll
type Poll struct {
	ID        string
	Closed    bool
	Responses map[string]*bfv.Ciphertext

	params *bfv.Parameters
	pk     *bfv.PublicKey
	rlk    *bfv.EvaluationKey
	result *bfv.Ciphertext
}

// NewPoll creates a new poll struct from an http form
func NewPoll(r *http.Request) (*Poll, error) {
	p := new(Poll)
	p.params = bfv.DefaultParams[1]
	utils.UnmarshalFromBase64(p.pk, r.FormValue("pk"))
	utils.UnmarshalFromBase64(p.rlk, r.FormValue("rlk"))
	p.Responses = make(map[string]*bfv.Ciphertext, 5)
	p.ID = utils.GetSha256Hex(p.pk)
	return p, nil
}

// RegisterResponse reads a new poll response from an http form
func (p *Poll) RegisterResponse(r *http.Request) error {
	name := r.FormValue("name")
	p.Responses[name] = new(bfv.Ciphertext)
	return utils.UnmarshalFromBase64(p.Responses[name], r.FormValue("ct"))
}

// Close computes the poll results and closes the poll
func (p *Poll) Close() {
	p.Closed = true
	if len(p.Responses) > 0 {
		eval := bfv.NewEvaluator(p.params)
		agg := make([]*bfv.Ciphertext, 0, len(p.Responses))

		// puts all the responses in an array
		for _, ct := range p.Responses {
			agg = append(agg, ct)
		}

		// aggregates the responses iteratively
		for len(agg) > 1 {
			agg = append(agg[2:], eval.RelinearizeNew(eval.MulNew(agg[0], agg[1]), p.rlk))
		}
		p.result = agg[0]
	}
}

// PublicDataJSON returns the public state of the poll struct as a JSON encoding Lattigo objects in base64.
func (p *Poll) PublicDataJSON() string {
	b, _ := json.Marshal(map[string]interface{}{
		"id":     p.ID,
		"pubkey": utils.MarshalToBase64String(p.pk),
		"result": utils.MarshalToBase64String(p.result),
		"closed": p.Closed,
	})
	return string(b)
}

func main() {

	// server state
	polls := make(map[string]*Poll)

	// page template
	pollTpl := template.Must(template.ParseFiles("poll.gohtml"))

	r := mux.NewRouter()

	// the root route: GET renders the poll creation button and POST handles the poll creation
	r.HandleFunc("/polls", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" { // creates the poll and responds its ID
			p, _ := NewPoll(r)
			polls[p.ID] = p
			rw.Write([]byte(p.ID))
			log.Println("Successfully created poll with ID", p.ID)
		} else {
			pollTpl.Execute(rw, nil) // renders the poll-creation page
		}
	})

	// the poll route: GET renders the poll state in HTML and POST registers new responses. For all methods,
	// a "closing" form values triggers the poll's closing and result computation.
	r.HandleFunc("/polls/{poll_id:[a-z0-9]+}", func(rw http.ResponseWriter, r *http.Request) {
		var p *Poll
		var exists bool

		// retreives the poll data
		if p, exists = polls[mux.Vars(r)["poll_id"]]; !exists {
			rw.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(rw, "Poll not found")
			return
		}

		// POST registers new answers to the poll
		if r.Method == "POST" && !p.Closed {
			if err := p.RegisterResponse(r); err != nil {
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			log.Println("received a new response from", r.FormValue("name"), ", total", len(p.Responses), "answers")
		}

		// performs the poll closing operation on request
		if r.FormValue("closing") != "" && !p.Closed {
			p.Close()
			log.Println("closed poll with id", p.ID)
		}

		// renders html representation of the poll state
		if err := pollTpl.Execute(rw, p); err != nil {
			log.Println(err)
		}
	})

	// binds the poll handlers
	http.Handle("/", r)

	// binds the static file server handler
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	log.Println("Starting server...")
	http.ListenAndServe(`:8080`, nil) // start the http server
}
