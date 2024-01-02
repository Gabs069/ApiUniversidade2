using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using apiUniversidade.Model;
using apiUniversidade.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace apiUniversidade.Controllers;

[Authorize(AuthenticationSchemes = "Bearer")]
[ApiController]
[Route("[controller]")]

public class AlunoController : ControllerBase
{
    private readonly ILogger<AlunoController> _logger;
    private readonly apiUniversidadeContext _context;

    public AlunoController(ILogger<AlunoController> logger, apiUniversidadeContext context)
    {
        _logger = logger;
        _context = context;
    }

    [HttpGet]
    public ActionResult<IEnumerable<Aluno>> Get()
    {
        var alunos = _context.Alunos.ToList();
        if(alunos is null)
            return NotFound();

        return alunos;
    }

    [HttpPost]
    public ActionResult Post(Aluno alunos)
    {
        _context.Alunos.Add(alunos);
        _context.SaveChanges();

        return new CreatedAtRouteResult("GetAluno",
        new{id = alunos.ID},
        alunos);
    }

    [HttpGet("{id:int}", Name="GetAluno")]
    public ActionResult<Aluno> Get(int id)
    {
        var alunos = _context.Alunos.FirstOrDefault(p => p.ID == id);
        if(alunos is null)
            return NotFound("Aluno não encontrado.");
        
        return alunos;
    }

    [HttpPut("{id:int}")]
    public ActionResult Put(int id, Aluno alunos)
    {
        if(id != alunos.ID)
            return BadRequest();

        _context.Entry(alunos).State = EntityState.Modified;
        _context.SaveChanges();

        return Ok(alunos);
    }

    [HttpDelete("{id:int}")]
    public ActionResult Delete(int id)
    {
        var alunos = _context.Alunos.FirstOrDefault(p => p.ID == id);

        if (alunos is null)
            return NotFound();

        _context.Alunos.Remove(alunos);
        _context.SaveChanges();

        return Ok(alunos);
    }
}