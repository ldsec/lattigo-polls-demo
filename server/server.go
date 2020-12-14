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
	ID           string
	Closed       bool
	Participants map[string]*bfv.Ciphertext

	pk  bfv.PublicKey
	rlk bfv.EvaluationKey

	responses []*bfv.Ciphertext
	result    *bfv.Ciphertext
}

// PollServer represents the state of the poll server.
type PollServer struct {
	*mux.Router
	bfv.Evaluator

	Polls map[string]*Poll
}

// NewPollServer creates a new poll server state
func NewPollServer(params *bfv.Parameters) *PollServer {
	return &PollServer{
		Router:    mux.NewRouter(),
		Evaluator: bfv.NewEvaluator(params),
		Polls:     make(map[string]*Poll),
	}
}

// NewPoll creates a new poll struct from an http form
func (ps *PollServer) NewPoll(r *http.Request) *Poll {
	p := new(Poll)
	utils.UnmarshalFromBase64(&p.pk, r.FormValue("pk"))
	utils.UnmarshalFromBase64(&p.rlk, r.FormValue("rlk"))
	p.Participants = make(map[string]*bfv.Ciphertext, 5)
	p.ID = utils.GetSha256Hex(&p.pk)
	ps.Polls[p.ID] = p
	return p
}

// RegisterResponse reads a new poll response from an http form
func (p *Poll) RegisterResponse(r *http.Request) error {
	name := r.FormValue("name")
	ct, update := p.Participants[name]
	if !update {
		ct = new(bfv.Ciphertext)
		p.responses = append(p.responses, ct)
		p.Participants[name] = ct
	}
	return utils.UnmarshalFromBase64(ct, r.FormValue("ct"))
}

// Close computes the polls' result and closes the poll
func (ps *PollServer) Close(p *Poll) {
	p.Closed = true
	if len(p.Participants) > 0 {
		agg := p.responses
		// aggregates the responses recursively
		for len(agg) > 1 {
			agg = append(agg[2:],
				ps.RelinearizeNew(
					ps.MulNew(agg[0], agg[1]), &p.rlk),
			)
		}
		p.result = agg[0]
	}
}

// PublicDataJSON returns the public state of the poll struct as a JSON encoding Lattigo objects in base64.
func (p *Poll) PublicDataJSON() string {
	b, _ := json.Marshal(map[string]interface{}{
		"id":     p.ID,
		"pubkey": utils.MarshalToBase64String(&p.pk),
		"result": utils.MarshalToBase64String(p.result),
		"closed": p.Closed,
	})
	return string(b)
}

func main() {

	// server state
	ps := NewPollServer(bfv.DefaultParams[1])

	// loads the page template
	pollTpl := template.Must(template.ParseFiles("poll.gohtml"))

	// the root route: GET renders the poll creation button and POST handles the poll creation
	ps.HandleFunc("/polls", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" { // creates the poll and responds its ID
			p := ps.NewPoll(r)
			rw.Write([]byte(p.ID))
			log.Println("Successfully created poll with ID", p.ID)
		} else {
			pollTpl.Execute(rw, nil) // renders the poll-creation page
		}
	})

	// the poll route: GET renders the poll state in HTML and POST registers new responses. For all methods,
	// a "closing" form values triggers the poll's closing and result computation.
	ps.HandleFunc("/polls/{poll_id:[a-z0-9]+}", func(rw http.ResponseWriter, r *http.Request) {
		var p *Poll
		var exists bool

		// retreives the poll data
		if p, exists = ps.Polls[mux.Vars(r)["poll_id"]]; !exists {
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
			log.Println("received a new response from", r.FormValue("name"), ", total", len(p.Participants), "answers")
		}

		// performs the poll closing operation on request
		if r.FormValue("closing") != "" && !p.Closed {
			ps.Close(p)
			log.Println("closed poll with id", p.ID)
		}

		// renders html representation of the poll state
		if err := pollTpl.Execute(rw, p); err != nil {
			log.Println(err)
		}
	})

	// binds the poll handlers
	http.Handle("/", ps)

	// binds the static file server handler
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	log.Println("Starting server...")
	http.ListenAndServe(`:8080`, nil) // start the http server
}
